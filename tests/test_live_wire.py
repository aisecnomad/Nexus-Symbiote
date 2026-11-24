"""Byte streams through the real http.client parser and a loopback TLS server.

Discovery refuses loopback destinations by design, so these tests replace only the
public-address resolver and, for TLS, trust a test certificate authority. Framing,
limits, deadlines and the TLS handshake run unmodified.
"""

from __future__ import annotations

import http.client
import io
import json
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.scanners import live_mcp as live

REQUEST = b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
RESULT = {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}


class WireSocket:
    """The TLS-side socket: replays fixed response bytes, at most ``step`` per read."""

    def __init__(self, incoming: bytes, *, step: int = 1 << 20, delay: float = 0.0) -> None:
        self.incoming = io.BytesIO(incoming)
        self.step, self.delay = step, delay
        self.sent: list[bytes] = []
        self.timeouts: list[float] = []
        self.closed = False
        self.connected: list[Any] = []

    def connect(self, address: Any) -> None:
        self.connected.append(address)

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def recv_into(self, buffer: Any) -> int:
        if self.delay:
            time.sleep(self.delay)
        raw = self.incoming.read(min(len(buffer), self.step))
        buffer[: len(raw)] = raw
        return len(raw)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


def wire(monkeypatch: pytest.MonkeyPatch, secured: WireSocket) -> live.PinnedHTTPTransport:
    context = ssl.create_default_context()
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(context, "wrap_socket", lambda stream, *, server_hostname: secured)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: WireSocket(b""))
    monkeypatch.setattr(live, "_resolve_public", lambda *a: (socket.AF_INET, "93.184.216.34"))
    return live.PinnedHTTPTransport()


def chunked(body: bytes, sizes: tuple[int, ...] = (5, 17, 1, 64)) -> bytes:
    out, index, turn = bytearray(), 0, 0
    while index < len(body):
        size = sizes[turn % len(sizes)]
        part = body[index : index + size]
        out += f"{len(part):x}\r\n".encode() + part + b"\r\n"
        index, turn = index + size, turn + 1
    return bytes(out + b"0\r\n\r\n")


def response(headers: list[tuple[str, str]], body: bytes) -> bytes:
    lines = "".join(f"{name}: {value}\r\n" for name, value in headers)
    return f"HTTP/1.1 200 OK\r\n{lines}\r\n".encode() + body


def sse(*messages: dict[str, Any]) -> bytes:
    return b"".join(
        b"event: message\r\ndata: " + json.dumps(message).encode() + b"\r\n\r\n"
        for message in messages
    )


def request(transport: live.PinnedHTTPTransport, *, max_bytes: int = 1 << 20) -> live.HTTPReply:
    return transport.request(
        "https://fixture.example/mcp", REQUEST, {}, timeout=2, max_bytes=max_bytes
    )


@pytest.mark.parametrize("step", [1, 7, 1 << 20])
def test_chunked_event_stream_is_decoded_before_event_parsing(monkeypatch, step):
    progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}
    body = sse(progress, RESULT)
    raw = response(
        [("Content-Type", "text/event-stream"), ("Transfer-Encoding", "chunked")], chunked(body)
    )
    reply = request(wire(monkeypatch, WireSocket(raw, step=step)))
    assert reply.body == body
    limits = live.DiscoveryLimits()
    assert live._response(reply, 2, limits) == RESULT["result"]


def test_chunked_json_reply_is_decoded(monkeypatch):
    body = json.dumps(RESULT).encode()
    raw = response(
        [("Content-Type", "application/json"), ("Transfer-Encoding", "chunked")], chunked(body)
    )
    assert request(wire(monkeypatch, WireSocket(raw, step=3))).body == body


def test_event_line_above_64_kib_is_accepted_up_to_the_response_limit(monkeypatch):
    large = {"jsonrpc": "2.0", "id": 2, "result": {"tools": [], "pad": "x" * 200_000}}
    body = sse(large)
    raw = response(
        [("Content-Type", "text/event-stream"), ("Transfer-Encoding", "chunked")], chunked(body)
    )
    assert request(wire(monkeypatch, WireSocket(raw))).body == body
    with pytest.raises(live.DiscoveryError, match="byte limit"):
        request(wire(monkeypatch, WireSocket(raw)), max_bytes=100_000)


def test_truncated_chunk_raises_an_http_error(monkeypatch):
    raw = response(
        [("Content-Type", "text/event-stream"), ("Transfer-Encoding", "chunked")],
        b"64\r\nevent: message\r\n",
    )
    with pytest.raises(http.client.HTTPException):
        request(wire(monkeypatch, WireSocket(raw)))


def test_truncated_reply_is_a_recorded_discovery_failure(monkeypatch):
    raw = response(
        [("Content-Type", "application/json"), ("Transfer-Encoding", "chunked")], b"ff\r\n{"
    )
    transport = wire(monkeypatch, WireSocket(raw))
    result = live.discover_tools(
        "https://fixture.example/mcp",
        allowed_origins=["https://fixture.example"],
        transport=transport,
    )
    assert not result.complete
    assert result.failures == [
        "Live MCP discovery refused or incomplete; check endpoint policy, protocol and configured limits."
    ]


def test_repeated_unused_headers_are_accepted_but_consumed_ones_are_not(monkeypatch):
    body = json.dumps(RESULT).encode()
    cookies = [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("Via", "1.1 a"), ("Via", "1.1 b")]
    raw = response(
        [("Content-Type", "application/json"), ("Content-Length", str(len(body))), *cookies],
        body,
    )
    assert request(wire(monkeypatch, WireSocket(raw))).body == body
    duplicate = response(
        [("Content-Type", "application/json"), ("Content-Type", "text/event-stream")], body
    )
    with pytest.raises(live.DiscoveryError, match="duplicate"):
        request(wire(monkeypatch, WireSocket(duplicate)))


@pytest.mark.parametrize(
    "raw,error",
    [
        (response([(f"X-H{i}", "v") for i in range(65)], b""), live.DiscoveryError),
        (response([(f"X-H{i}", "v") for i in range(101)], b""), http.client.HTTPException),
        (response([("X-Long", "v" * 70_000)], b""), http.client.HTTPException),
        (b"HTTP/1.1 100 Continue\r\n\r\n" * 50, http.client.HTTPException),
        (b"NOT-HTTP\r\n\r\n", http.client.HTTPException),
    ],
)
def test_header_floods_long_lines_and_interim_responses_are_refused(monkeypatch, raw, error):
    with pytest.raises(error):
        request(wire(monkeypatch, WireSocket(raw)))


def test_slow_body_stops_at_the_request_deadline(monkeypatch):
    body = sse(RESULT)
    raw = response([("Content-Type", "text/event-stream")], body)
    transport = wire(monkeypatch, WireSocket(raw, step=1, delay=0.02))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        transport.request("https://fixture.example/mcp", REQUEST, {}, timeout=0.3, max_bytes=1000)
    assert time.monotonic() - started < 2


@pytest.mark.parametrize(
    "address",
    [
        "fec0::1",
        "5f00::1",
        "3fff::1",
        "2001:db8::1",
        "2001:2::1",
        "100::1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "2002:7f00:1::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "100.64.0.1",
        "198.18.0.1",
        "192.0.0.9",
        "192.88.99.1",
        "240.0.0.1",
        "255.255.255.255",
    ],
)
def test_special_purpose_destinations_are_refused_whatever_the_interpreter_says(address):
    with pytest.raises(live.DiscoveryError):
        live._resolve_public(address, 443, 1)


def test_public_destinations_are_still_accepted():
    for address in ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"):
        assert live._public_ip(address)


def test_live_tls_context_never_writes_session_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    connection = live._PinnedHTTPSConnection(
        "fixture.example", 443, socket.AF_INET, "93.184.216.34", 1.0
    )
    assert connection._tls_context.keylog_filename is None


def _pki(tmp_path: Path) -> tuple[bytes, Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nexus-symbiote test CA")])
    usage = {
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "encipher_only": False,
        "decipher_only": False,
    }
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, **usage),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.example")]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, **usage),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "leaf.pem", tmp_path / "leaf.key"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca.public_bytes(serialization.Encoding.PEM), cert_path, key_path


class LoopbackTLSServer(threading.Thread):
    """Answer one TLS connection with fixed bytes, or accept it and stay silent."""

    def __init__(self, cert: Path, key: Path, reply: bytes | None) -> None:
        super().__init__(daemon=True)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.reply = reply
        self.received = b""
        self.error: OSError | None = None
        self._stop_event = threading.Event()

    def run(self) -> None:
        try:
            self._serve()
        except OSError as exc:  # includes ssl.SSLError when a test client refuses the peer
            self.error = exc

    def _serve(self) -> None:
        connection, _ = self.listener.accept()
        with connection:
            if self.reply is None:
                self._stop_event.wait(timeout=2)
                return
            with self.context.wrap_socket(connection, server_side=True) as stream:
                while b"\r\n\r\n" not in self.received:
                    self.received += stream.recv(65536)
                head, _, body = self.received.partition(b"\r\n\r\n")
                length = int(
                    next(
                        line.split(b":", 1)[1]
                        for line in head.split(b"\r\n")
                        if line.lower().startswith(b"content-length:")
                    )
                )
                while len(body) < length:
                    body += stream.recv(65536)
                stream.sendall(self.reply)

    def close(self) -> None:
        self._stop_event.set()
        self.listener.close()


def _trust(monkeypatch: pytest.MonkeyPatch, ca: bytes) -> None:
    original = ssl.create_default_context
    monkeypatch.setattr(ssl, "create_default_context", lambda: original(cadata=ca.decode("ascii")))
    monkeypatch.setattr(live, "_resolve_public", lambda *a: (socket.AF_INET, "127.0.0.1"))


def test_chunked_event_stream_over_real_tls_with_keylog_requested(monkeypatch, tmp_path):
    ca, cert, key = _pki(tmp_path)
    body = sse(RESULT)
    reply = response(
        [
            ("Content-Type", "text/event-stream"),
            ("Transfer-Encoding", "chunked"),
            ("Connection", "close"),
        ],
        chunked(body),
    )
    server = LoopbackTLSServer(cert, key, reply)
    server.start()
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    _trust(monkeypatch, ca)
    try:
        result = live.PinnedHTTPTransport().request(
            f"https://fixture.example:{server.port}/mcp",
            REQUEST,
            {"Content-Type": "application/json"},
            timeout=5,
            max_bytes=1 << 20,
        )
    finally:
        server.join(10)
        server.close()
    assert result.body == body
    assert b"POST /mcp HTTP/1.1" in server.received
    text = keylog.read_text() if keylog.exists() else ""
    assert "SECRET" not in text and "CLIENT_RANDOM" not in text


def test_tls_handshake_that_never_completes_stops_at_the_deadline(monkeypatch, tmp_path):
    ca, cert, key = _pki(tmp_path)
    server = LoopbackTLSServer(cert, key, None)
    server.start()
    _trust(monkeypatch, ca)
    started = time.monotonic()
    try:
        with pytest.raises((OSError, ssl.SSLError)):
            live.PinnedHTTPTransport().request(
                f"https://fixture.example:{server.port}/mcp",
                REQUEST,
                {},
                timeout=0.5,
                max_bytes=1000,
            )
        elapsed = time.monotonic() - started
    finally:
        server.close()
        server.join(10)
    assert elapsed < 2.5


def test_certificate_for_another_name_is_refused(monkeypatch, tmp_path):
    ca, cert, key = _pki(tmp_path)
    server = LoopbackTLSServer(cert, key, b"HTTP/1.1 200 OK\r\n\r\n")
    server.start()
    _trust(monkeypatch, ca)
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            live.PinnedHTTPTransport().request(
                f"https://other.example:{server.port}/mcp", REQUEST, {}, timeout=3, max_bytes=100
            )
    finally:
        server.close()
        server.join(10)
