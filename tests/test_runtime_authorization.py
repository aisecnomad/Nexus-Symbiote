from __future__ import annotations

import base64
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.runtime import (
    ActionApproval,
    ApprovedSnapshot,
    AuthorizationError,
    Envelope,
    EnvelopeSignature,
    ExecutionContext,
    ReferenceGateway,
    ServedTool,
    StateStore,
    ToolCall,
    ToolGrant,
    TrustStatus,
    _pae,
    canonical_bytes,
    digest,
    key_id,
    sign_contract,
    strict_json,
    verify_contract,
)

NOW = datetime(2026, 11, 1, tzinfo=UTC)
POLICY = "sha256:" + "a" * 64
DEFINITION = {"name": "send", "description": "Send a message", "inputSchema": {"type": "object"}}


def fixture(tmp_path: Path, *, serial: int = 1):
    release, human, status = (Ed25519PrivateKey.generate() for _ in range(3))
    context = ExecutionContext(
        agent_id="agent:triage",
        deployment_id="prod",
        tenant="acme",
        workload_identity="spiffe://acme/triage",
        policy_digest=POLICY,
    )
    call = ToolCall(
        server_id="server:mail",
        tool_name="send",
        action="send",
        resource="mailbox:team",
        arguments={"to": "team@example.test"},
    )
    bom = {"agent": "triage", "tools": ["send"]}
    grant = ToolGrant(
        server_id="server:mail",
        endpoint_identity="https://mail.example.test/mcp",
        tool_name="send",
        definition_digest=hash_tool_definition(
            "send", DEFINITION["description"], DEFINITION["inputSchema"]
        ),
        actions=("send",),
        resources=("mailbox:team",),
    )
    snapshot = ApprovedSnapshot(
        **context.model_dump(),
        serial=serial,
        bom_digest=digest(bom),
        tools=(grant,),
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(hours=1),
    )
    statuses = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(minutes=30),
    )
    approval = ActionApproval(
        snapshot_digest=digest(snapshot.model_dump(mode="json")),
        context_digest=digest(context.model_dump(mode="json")),
        request_digest=digest(call.model_dump(mode="json")),
        nonce="c3f1b0a7d9e24f6b8a1c5d7e9f0b2a4c",
        actor="approver",
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(minutes=1),
    )
    executed = []
    gateway = ReferenceGateway(
        snapshot_keys={key_id(release.public_key()): release.public_key()},
        approval_keys={key_id(human.public_key()): human.public_key()},
        trust_keys={key_id(status.public_key()): status.public_key()},
        state=StateStore(tmp_path / "state.sqlite"),
        authenticate=lambda: context,
        describe=lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity, definition=DEFINITION
        ),
        execute=lambda c: executed.append(c) or "executed",
        approval_actors={key_id(human.public_key()): "approver"},
        clock=lambda: NOW,
        resolve_scope=lambda c: (
            "send",
            "mailbox:team" if c.arguments.get("to") == "team@example.test" else "mailbox:admin",
        ),
    )
    return gateway, call, bom, snapshot, statuses, approval, release, human, status, executed


def invoke(values, **changes):
    gateway, call, bom, snapshot, statuses, approval, release, human, status, _ = values
    kwargs = {
        "snapshot": sign_contract(snapshot, "snapshot", (release,)),
        "trust": sign_contract(statuses, "trust", (status,)),
        "approval": sign_contract(approval, "approval", (human,)),
        "bom": bom,
    }
    kwargs.update(changes)
    if "now" in kwargs:
        clock_value = kwargs.pop("now")
        gateway.clock = lambda: clock_value
    return gateway.invoke(call, **kwargs)


def test_gateway_executes_approved_call_and_consumes_approval(tmp_path):
    values = fixture(tmp_path)
    assert invoke(values) == "executed"
    with pytest.raises(AuthorizationError, match="already been used"):
        invoke(values)
    assert len(values[-1]) == 1


def test_scope_resolver_cannot_modify_request_during_resolution(tmp_path):
    values = fixture(tmp_path)
    gateway = values[0]

    def mutate(call):
        call.arguments["to"] = "admin@example.test"
        return "send", "mailbox:team"

    gateway.resolve_scope = mutate
    with pytest.raises(AuthorizationError, match="resolver modified"):
        invoke(values)
    assert values[-1] == []


def test_scope_resolver_cannot_mutate_request_after_approval_check(tmp_path):
    values = fixture(tmp_path)
    gateway, original, _, _, _, _, _, _, _, executed = values
    context = gateway.authenticate()
    retained = []
    auth_calls = 0

    def resolve(call):
        retained.append(call)
        return "send", "mailbox:team"

    def authenticate():
        nonlocal auth_calls
        auth_calls += 1
        if auth_calls == 2:
            retained[0].arguments["to"] = "admin@example.test"
        return context

    gateway.resolve_scope = resolve
    gateway.authenticate = authenticate
    assert invoke(values) == "executed"
    assert executed[0].arguments == {"to": "team@example.test"}
    assert original.arguments == {"to": "team@example.test"}


@pytest.mark.parametrize(
    "failure",
    [
        "missing-approval",
        "changed-args",
        "wrong-tenant",
        "wrong-endpoint",
        "changed-description",
        "revoked-tool",
        "revoked-signer",
        "expired",
        "future",
        "bom-tampered",
        "wrong-policy",
        "wrong-resource",
        "wrong-signer",
        "unknown-descriptor-field",
    ],
)
def test_gateway_denies_without_side_effects(tmp_path, failure):
    values = list(fixture(tmp_path))
    gateway, call, bom, snapshot, statuses, approval, release, human, status, executed = values
    changes = {}
    if failure == "missing-approval":
        changes["approval"] = None
    elif failure == "changed-args":
        values[1] = call.model_copy(update={"arguments": {"to": "attacker@example.test"}})
    elif failure == "wrong-tenant":
        original = gateway.authenticate()
        gateway.authenticate = lambda: original.model_copy(update={"tenant": "other"})
    elif failure == "wrong-endpoint":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity="https://attacker.example.test", definition=DEFINITION
        )
    elif failure == "changed-description":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=snapshot.tools[0].endpoint_identity,
            definition={**DEFINITION, "description": "Steal secrets"},
        )
    elif failure == "revoked-tool":
        values[4] = statuses.model_copy(
            update={"revoked_tools": (snapshot.tools[0].definition_digest,)}
        )
    elif failure == "revoked-signer":
        values[4] = statuses.model_copy(update={"revoked_signers": (key_id(release.public_key()),)})
    elif failure == "expired":
        changes["now"] = NOW + timedelta(hours=2)
    elif failure == "future":
        values[3] = snapshot.model_copy(update={"not_before": NOW + timedelta(minutes=1)})
    elif failure == "bom-tampered":
        changes["bom"] = {**bom, "tools": ["send", "steal"]}
    elif failure == "wrong-policy":
        original = gateway.authenticate()
        gateway.authenticate = lambda: original.model_copy(
            update={"policy_digest": "sha256:" + "b" * 64}
        )
    elif failure == "wrong-resource":
        values[1] = call.model_copy(update={"resource": "mailbox:admin"})
    elif failure == "wrong-signer":
        changes["snapshot"] = sign_contract(snapshot, "snapshot", (human,))
    elif failure == "unknown-descriptor-field":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=snapshot.tools[0].endpoint_identity,
            definition={**DEFINITION, "outputSchema": {}},
        )
    with pytest.raises(AuthorizationError):
        invoke(values, **changes)
    assert executed == []


def test_threshold_counts_distinct_authorized_keys(tmp_path):
    values = fixture(tmp_path)
    snapshot, key = values[3], values[6]
    envelope = sign_contract(snapshot, "snapshot", (key,))
    duplicate = envelope.model_copy(update={"signatures": envelope.signatures * 2})
    ring = {key_id(key.public_key()): key.public_key()}
    with pytest.raises(AuthorizationError):
        verify_contract(duplicate, "snapshot", ring, threshold=2)
    other = Ed25519PrivateKey.generate()
    ring[key_id(other.public_key())] = other.public_key()
    verified, accepted = verify_contract(
        sign_contract(snapshot, "snapshot", (key, other)), "snapshot", ring, threshold=2
    )
    assert verified == snapshot and len(accepted) == 2
    with pytest.raises(AuthorizationError):
        verify_contract(envelope, "snapshot", ring, threshold=0)


def test_statement_type_and_payload_tampering_rejected(tmp_path):
    values = fixture(tmp_path)
    key = values[6]
    envelope = sign_contract(values[3], "snapshot", (key,))
    ring = {key_id(key.public_key()): key.public_key()}
    with pytest.raises(AuthorizationError):
        verify_contract(envelope, "approval", ring)
    statement = json.loads(base64.b64decode(envelope.payload))
    statement["predicate"]["serial"] = 900
    altered = envelope.model_copy(
        update={"payload": base64.b64encode(json.dumps(statement).encode()).decode()}
    )
    with pytest.raises(AuthorizationError):
        verify_contract(altered, "snapshot", ring)
    wire = envelope.model_dump(mode="json", by_alias=True)
    assert "payloadType" in wire and "keyid" in wire["signatures"][0]
    assert Envelope.model_validate(wire) == envelope


def test_verifier_records_high_water_mark_and_rejects_fork(tmp_path):
    store = StateStore(tmp_path / "state.sqlite")
    store.record((("snapshot:acme/prod", 10, "digest10"),))
    reopened = StateStore(tmp_path / "state.sqlite")
    with pytest.raises(AuthorizationError):
        reopened.record((("snapshot:acme/prod", 9, "digest9"),))
    with pytest.raises(AuthorizationError):
        reopened.record((("snapshot:acme/prod", 10, "other"),))
    reopened.record((("snapshot:acme/prod", 11, "digest11"),))


def test_failed_authorization_does_not_poison_state(tmp_path):
    values = fixture(tmp_path)
    with pytest.raises(AuthorizationError):
        invoke(values, approval=None)
    assert invoke(values) == "executed"


def test_actual_argument_scope_cannot_bypass_autonomous_grant(tmp_path):
    values = list(fixture(tmp_path))
    grant = values[3].tools[0].model_copy(update={"require_approval": False})
    values[3] = values[3].model_copy(update={"tools": (grant,)})
    values[1] = values[1].model_copy(update={"arguments": {"to": "admin@example.test"}})
    with pytest.raises(AuthorizationError, match="actual tool arguments"):
        invoke(values, approval=None)
    assert values[-1] == []


def test_new_revocation_is_remembered_even_when_call_is_denied(tmp_path):
    values = list(fixture(tmp_path))
    old_status = values[4]
    values[4] = old_status.model_copy(
        update={"serial": 2, "revoked_tools": (values[3].tools[0].definition_digest,)}
    )
    with pytest.raises(AuthorizationError, match="revoked"):
        invoke(values)
    values[4] = old_status
    with pytest.raises(AuthorizationError, match="rollback"):
        invoke(values)
    assert values[-1] == []


def test_revoked_trust_signer_cannot_reinstate_itself(tmp_path):
    values = list(fixture(tmp_path))
    gateway, _, _, snapshot, status, _, _, _, authority, executed = values
    other = Ed25519PrivateKey.generate()
    other_id = key_id(other.public_key())
    gateway.trust_keys[other_id] = other.public_key()
    revoked = status.model_copy(
        update={
            "serial": 2,
            "revoked_signers": (other_id,),
            "revoked_tools": (snapshot.tools[0].definition_digest,),
        }
    )
    with pytest.raises(AuthorizationError, match="tool or endpoint is revoked"):
        invoke(values, trust=sign_contract(revoked, "trust", (authority,)))
    gateway.state = StateStore(tmp_path / "state.sqlite")
    clear = status.model_copy(update={"serial": 3})
    with pytest.raises(AuthorizationError, match="previously revoked"):
        invoke(values, trust=sign_contract(clear, "trust", (other,)))
    assert executed == []

    # A still-authorized issuer may restore B. B can then issue a later status.
    with pytest.raises(AuthorizationError, match="operation-bound approval required"):
        invoke(values, trust=sign_contract(clear, "trust", (authority,)), approval=None)
    later = status.model_copy(update={"serial": 4})
    assert invoke(values, trust=sign_contract(later, "trust", (other,))) == "executed"
    assert len(executed) == 1


def test_legacy_trust_head_requires_exact_status_for_migration(tmp_path):
    values = fixture(tmp_path)
    gateway, _, _, _, status, _, _, _, authority, _ = values
    legacy = tmp_path / "legacy.sqlite"
    other = Ed25519PrivateKey.generate()
    other_id = key_id(other.public_key())
    gateway.trust_keys[other_id] = other.public_key()
    expired = status.model_copy(
        update={
            "revoked_signers": (other_id,),
            "not_before": NOW - timedelta(hours=2),
            "not_after": NOW - timedelta(hours=1),
        }
    )
    db = sqlite3.connect(legacy)
    with db:
        db.execute("CREATE TABLE heads (scope TEXT PRIMARY KEY, serial INTEGER, digest TEXT)")
        db.execute(
            "INSERT INTO heads VALUES (?, ?, ?)",
            ("trust:acme", expired.serial, digest(expired.model_dump(mode="json"))),
        )
        db.execute("CREATE TABLE nonces (nonce TEXT PRIMARY KEY)")
        db.execute("INSERT INTO nonces VALUES ('legacy-consumed-nonce')")
    db.close()

    gateway.state = StateStore(legacy)
    next_status = status.model_copy(update={"serial": 2})
    with pytest.raises(AuthorizationError, match="restore the recorded trust status"):
        invoke(values, trust=sign_contract(next_status, "trust", (other,)))
    with pytest.raises(AuthorizationError, match="does not match"):
        gateway.state.restore_trust_status(status)
    gateway.state.restore_trust_status(expired)
    with pytest.raises(AuthorizationError, match="expired"):
        invoke(values, trust=sign_contract(expired, "trust", (authority,)))
    with pytest.raises(AuthorizationError, match="previously revoked"):
        invoke(values, trust=sign_contract(next_status, "trust", (other,)))
    with pytest.raises(AuthorizationError, match="already been used"):
        gateway.state.record((), "legacy-consumed-nonce")
    assert invoke(values, trust=sign_contract(next_status, "trust", (authority,))) == "executed"


def test_concurrent_trust_advance_rejects_inflight_call_without_consuming_nonce(tmp_path):
    values = fixture(tmp_path)
    gateway, _, _, _, status, _, _, _, authority, executed = values
    second = StateStore(tmp_path / "state.sqlite")
    other_id = key_id(Ed25519PrivateKey.generate().public_key())
    revoked = status.model_copy(update={"serial": 2, "revoked_signers": (other_id,)})
    describe = gateway.describe

    def observe_new_status(server, tool):
        second.accept_trust_status(revoked, {key_id(authority.public_key())})
        return describe(server, tool)

    gateway.describe = observe_new_status
    with pytest.raises(AuthorizationError, match="rollback/fork"):
        invoke(values)
    assert executed == []
    gateway.describe = describe
    assert invoke(values, trust=sign_contract(revoked, "trust", (authority,))) == "executed"


def test_revocation_during_final_authentication_denies_pending_invocation(tmp_path):
    values = fixture(tmp_path)
    gateway, _, _, snapshot, status, _, _, _, authority, executed = values
    context = gateway.authenticate()
    first_auth = True
    final_auth_started = Event()
    resume_final_auth = Event()

    def authenticate():
        nonlocal first_auth
        if first_auth:
            first_auth = False
        else:
            final_auth_started.set()
            assert resume_final_auth.wait(timeout=5)
        return context

    gateway.authenticate = authenticate
    second = StateStore(tmp_path / "state.sqlite")
    revoked = status.model_copy(
        update={"serial": 2, "revoked_tools": (snapshot.tools[0].definition_digest,)}
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(invoke, values)
        try:
            assert final_auth_started.wait(timeout=5)
            second.accept_trust_status(revoked, {key_id(authority.public_key())})
        finally:
            resume_final_auth.set()
        with pytest.raises(AuthorizationError, match="rollback/fork"):
            pending.result(timeout=5)
    assert executed == []
    # Preserve the original approval when admission fails.
    restored = status.model_copy(update={"serial": 3})
    assert invoke(values, trust=sign_contract(restored, "trust", (authority,))) == "executed"


def test_expiry_is_rechecked_after_slow_adapter(tmp_path):
    values = fixture(tmp_path)
    gateway = values[0]
    describe = gateway.describe

    def delayed(server, tool):
        gateway.clock = lambda: NOW + timedelta(hours=2)
        return describe(server, tool)

    gateway.describe = delayed
    with pytest.raises(AuthorizationError, match="expired"):
        invoke(values)
    assert values[-1] == []


@pytest.mark.parametrize(
    "schema",
    [{"type": "object", "required": ["amount"]}, {"$ref": "https://attacker.example.test/schema"}],
)
def test_invalid_or_external_schema_cannot_execute(tmp_path, schema):
    values = list(fixture(tmp_path))
    definition = {**DEFINITION, "inputSchema": schema}
    grant = (
        values[3]
        .tools[0]
        .model_copy(
            update={
                "definition_digest": hash_tool_definition(
                    "send", definition["description"], schema
                ),
                "require_approval": False,
            }
        )
    )
    values[3] = values[3].model_copy(update={"tools": (grant,)})
    values[0].describe = lambda *_: ServedTool(
        endpoint_identity=grant.endpoint_identity, definition=definition
    )
    with pytest.raises(AuthorizationError, match="offline input schema"):
        invoke(values, approval=None)
    assert values[-1] == []


def test_approval_actor_must_match_authorized_key(tmp_path):
    values = list(fixture(tmp_path))
    values[5] = values[5].model_copy(update={"actor": "other-approver"})
    with pytest.raises(AuthorizationError, match="actor"):
        invoke(values)
    assert values[-1] == []


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"n":NaN}', '{"n":Infinity}'])
def test_noncanonical_input_rejected(raw):
    with pytest.raises(AuthorizationError):
        strict_json(raw)


def test_nonces_are_scoped_by_tenant_and_legacy_rows_stay_consumed(tmp_path):
    store = StateStore(tmp_path / "state.sqlite")
    store.record((), "shared-nonce", tenant="acme")
    store.record((), "shared-nonce", tenant="globex")
    with pytest.raises(AuthorizationError, match="already been used"):
        store.record((), "shared-nonce", tenant="acme")
    with sqlite3.connect(tmp_path / "state.sqlite") as db:
        db.execute("INSERT INTO nonces VALUES ('legacy-consumed-nonce')")
    for tenant in ("acme", "globex", None):
        with pytest.raises(AuthorizationError, match="already been used"):
            store.record((), "legacy-consumed-nonce", tenant=tenant)


def test_library_validation_errors_name_fields_without_values(tmp_path):
    values = fixture(tmp_path)
    key = values[6]
    envelope = sign_contract(values[3], "snapshot", (key,))
    ring = {key_id(key.public_key()): key.public_key()}
    statement = json.loads(base64.b64decode(envelope.payload))
    statement["predicate"]["not_before"] = "2026-10-31T23:59:59"
    statement["predicate"]["unexpected_key"] = "SECRET-VALUE-0001"
    payload = canonical_bytes(statement)
    altered = Envelope(
        payload=base64.b64encode(payload).decode(),
        signatures=(
            EnvelopeSignature(
                key_id=key_id(key.public_key()),
                signature=base64.b64encode(key.sign(_pae(payload))).decode(),
            ),
        ),
    )
    with pytest.raises(AuthorizationError) as excinfo:
        verify_contract(altered, "snapshot", ring)
    message = str(excinfo.value)
    assert "SECRET-VALUE-0001" not in message and "23:59:59" not in message
    assert "not_before" in message and "unsupported field" in message
