"""
test_t364_stratoshark_sofort_hebel-Epic Phase 0+1 (F-B + F-A).

F-B (TLS-Banner-Fix): TLS-Ports (443/8443) werden per echtem TLS-Handshake
gefingerprintet (Version/Cipher/ALPN), NICHT mehr mit einem toten Plaintext-
HEAD. Read-only, ohne Zertifikats-/PII-Inhalt im Banner.

F-A (§202c): Die network_scanner-GUI darf ``extern_erlaubt`` NIE auf True
hartkodieren — externe Scans laufen ausschließlich über Service/API mit
expliziter Bestätigung (§202c StGB / §126 ÖStGB).

Author: Patrick Riederich
"""

from __future__ import annotations

import re
import socket
import ssl
import threading
from pathlib import Path

from tools.network_scanner.data.socket_scanner import (
    _HTTP_PLAIN_PORTS,
    _TLS_PORTS,
    SocketScanner,
)

#: Distinktiver Marker im Test-Zert-Subject — darf NIE im Banner auftauchen.
_CN_CANARY = "PII-CANARY-DO-NOT-LEAK-MUSTERMANN"


class _FakeSocket:
    """Socket-Double: zeichnet sendall auf, liefert eine feste recv-Antwort."""

    def __init__(self, recv_data: bytes = b"SSH-2.0-OpenSSH_9.6\r\n") -> None:
        self.sent: list[bytes] = []
        self._recv = recv_data

    def settimeout(self, _t: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int) -> bytes:
        return self._recv[:n]


# ─────────────────────────────────────────────────────────────────────────────
# F-B Dispatch — TLS-Ports umgehen den Plaintext-HEAD
# ─────────────────────────────────────────────────────────────────────────────
class TestTlsDispatch:
    def test_tls_ports_route_to_handshake_no_plaintext(self, monkeypatch):
        scanner = SocketScanner()
        monkeypatch.setattr(scanner, "_grab_tls_banner", lambda _s: "TLS-SENTINEL")
        for port in (443, 8443):
            fake = _FakeSocket()
            assert scanner._grab_banner(fake, port) == "TLS-SENTINEL"
            assert fake.sent == [], f"Port {port}: kein Plaintext-HEAD erlaubt"

    def test_http_ports_still_send_head(self):
        scanner = SocketScanner()
        fake = _FakeSocket(recv_data=b"HTTP/1.1 200 OK\r\nServer: x\r\n")
        banner = scanner._grab_banner(fake, 80)
        assert fake.sent and fake.sent[0].startswith(b"HEAD ")
        assert "HTTP/1.1 200 OK" in banner

    def test_tls_and_http_port_sets_disjoint(self):
        # Regressionsschutz: 443/8443 duerfen nicht (wieder) in den HEAD-Pfad.
        assert _TLS_PORTS.isdisjoint(_HTTP_PLAIN_PORTS)
        assert {443, 8443} <= _TLS_PORTS


# ─────────────────────────────────────────────────────────────────────────────
# F-B Integration — echter Handshake gegen ephemeren self-signed-Server
# ─────────────────────────────────────────────────────────────────────────────
def _ephemeral_self_signed() -> tuple[bytes, bytes]:
    """Erzeugt (cert_pem, key_pem) eines self-signed localhost-Zertifikats."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Distinktiver CN-Kanarienvogel: belegt strukturell, dass KEIN Zert-Subject
    # ins Banner leakt (das Banner darf nur Version/Cipher/ALPN enthalten).
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CN_CANARY)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


def test_real_tls_handshake_banner(tmp_path):
    cert_pem, key_pem = _ephemeral_self_signed()
    cert_file = tmp_path / "c.pem"
    key_file = tmp_path / "k.pem"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)

    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve() -> None:
        try:
            raw, _ = listener.accept()
            with srv_ctx.wrap_socket(raw, server_side=True):
                pass  # Handshake genuegt; kein Payload austauschen
        except OSError:
            pass

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
        sock.settimeout(3.0)
        banner = SocketScanner._grab_tls_banner(sock)
    finally:
        listener.close()
        thread.join(timeout=3.0)

    # Banner-Form: nur ausgehandelte TLS-Metadaten (Version + Cipher [+ ALPN]).
    assert re.match(r"^TLSv1\.[0-9] \S+", banner), f"unerwartetes Banner: {banner!r}"
    # Load-bearing: der distinktive Zert-CN darf NICHT geleakt sein (DSGVO/PII).
    assert _CN_CANARY not in banner
    assert "CN=" not in banner


def test_tls_banner_failsafe_on_non_tls(tmp_path):
    """Spricht ein Nicht-TLS-Dienst auf dem Port, faellt der Handshake fail-safe."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve_plain() -> None:
        try:
            raw, _ = listener.accept()
            raw.recv(64)  # Client-Hello verwerfen
            raw.sendall(b"PLAINTEXT\r\n")
            raw.close()
        except OSError:
            pass

    thread = threading.Thread(target=_serve_plain, daemon=True)
    thread.start()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
        sock.settimeout(3.0)
        banner = SocketScanner._grab_tls_banner(sock)
    finally:
        listener.close()
        thread.join(timeout=3.0)

    # Kein Crash; entweder leer oder die Handshake-Fehlschlag-Notiz.
    assert banner in ("", "TLS (Handshake fehlgeschlagen)")


# ─────────────────────────────────────────────────────────────────────────────
# F-A — §202c: GUI verdrahtet extern_erlaubt NIE auf True
# ─────────────────────────────────────────────────────────────────────────────
class TestExtern202cGui:
    _GUI_DIR = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "network_scanner"
        / "gui"
    )

    def test_gui_never_hardcodes_extern_erlaubt_true(self):
        # Der Service-Gate selbst (externe IP/Hostname blockiert, §202c) ist in
        # test_network_scanner.py abgedeckt; HIER der GUI-Regressionsschutz: die
        # Oberflaeche darf den Gate NIE per hartkodiertem extern_erlaubt=True
        # umgehen (externe Scans nur ueber Service/API mit Bestaetigung).
        pattern = re.compile(r"extern_erlaubt\s*=\s*True")
        offenders = [
            py.name
            for py in self._GUI_DIR.rglob("*.py")
            if pattern.search(py.read_text(encoding="utf-8"))
        ]
        assert offenders == [], (
            "extern_erlaubt=True hartkodiert in der GUI "
            f"(§202c-Bruch): {offenders}"
        )
