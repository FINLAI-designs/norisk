"""
socket_scanner — Stdlib-basierter TCP-Port-Scanner.

Verwendet Python-Stdlib (socket + ThreadPoolExecutor) ohne externe
Abhängigkeiten. Führt Banner-Grabs durch und liefert PortInfo-Objekte.

Sicherheitsdesign:
  - Nur TCP-Connect-Scan (kein SYN-Scan, kein Root nötig)
  - Banner-Grab mit kurzen Timeouts (kein Hänger)
  - Keine Logging-Ausgabe von Banner-Inhalten (Privacy)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import get_logger
from tools.network_scanner.domain.interfaces import IScannerBackend
from tools.network_scanner.domain.models import HostInfo, PortInfo, PortState

log = get_logger(__name__)

# Standard-Port-Liste: 35 relevante Ports
DEFAULT_PORTS: list[int] = [
    21,
    22,
    23,
    25,
    53,
    69,
    80,
    110,
    111,
    135,
    139,
    143,
    161,
    389,
    443,
    445,
    465,
    512,
    513,
    514,
    587,
    636,
    993,
    995,
    1433,
    1521,
    2049,
    2181,
    3306,
    3389,
    4444,
    5432,
    5900,
    6379,
    8080,
]

_CONNECT_TIMEOUT = 1.0  # Sekunden pro Port-Verbindungsversuch
_BANNER_TIMEOUT = 0.5  # Sekunden für Banner-Lesen
_MAX_BANNER_BYTES = 256  # Maximale Banner-Länge
_MAX_WORKERS = 50  # Parallele Threads

#: Ports mit TLS — Banner via Handshake statt totem Plaintext-HEAD (F-B/).
_TLS_PORTS = frozenset({443, 8443})
#: Plaintext-HTTP-Ports — minimaler HEAD-Request liefert die erste Banner-Zeile.
_HTTP_PLAIN_PORTS = frozenset({80, 8080})


class SocketScanner(IScannerBackend):
    """TCP-Port-Scanner auf Basis von Python-stdlib socket.

    Verwendet ThreadPoolExecutor für paralleles Scannen.
    Keine Admin-Rechte nötig (nur TCP-Connect).

    Args:
        timeout: Verbindungs-Timeout in Sekunden.
        max_workers: Maximale Anzahl paralleler Scan-Threads.
    """

    def __init__(
        self,
        timeout: float = _CONNECT_TIMEOUT,
        max_workers: int = _MAX_WORKERS,
    ) -> None:
        """Initialisiert den Scanner."""
        self._timeout = timeout
        self._max_workers = max_workers

    def ist_verfuegbar(self) -> bool:
        """Immer True — kein externes Binary nötig.

        Returns:
            True.
        """
        return True

    def scan_host(
        self,
        host: str,
        ports: list[int],
    ) -> HostInfo:
        """Scannt einen Host parallel auf allen angegebenen Ports.

        Args:
            host: IP-Adresse oder Hostname.
            ports: Liste der zu scannenden Port-Nummern.

        Returns:
            HostInfo mit offenen Ports und Scan-Dauer.
        """
        t0 = time.monotonic()
        offene_ports: list[PortInfo] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            future_to_port = {pool.submit(self._scan_port, host, p): p for p in ports}
            for future in as_completed(future_to_port):
                result = future.result()
                if result is not None and result.state == PortState.OPEN:
                    offene_ports.append(result)

        offene_ports.sort(key=lambda p: p.port)
        erreichbar = len(offene_ports) > 0 or self._ping_host(host)
        dauer = time.monotonic() - t0

        log.debug(
            "Socket-Scan %s: %d offene Ports in %.1fs",
            host,
            len(offene_ports),
            dauer,
        )
        return HostInfo(
            host=host,
            erreichbar=erreichbar,
            offene_ports=offene_ports,
            scan_dauer_s=dauer,
        )

    def _scan_port(self, host: str, port: int) -> PortInfo | None:
        """Prüft ob ein einzelner Port offen ist und grabbt das Banner.

        Args:
            host: Ziel-Host.
            port: Zu prüfender Port.

        Returns:
            PortInfo oder None bei Fehler.
        """
        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                banner = self._grab_banner(sock, port)
                return PortInfo(
                    port=port,
                    state=PortState.OPEN,
                    banner=banner,
                )
        except (ConnectionRefusedError, OSError):
            return PortInfo(port=port, state=PortState.CLOSED)
        except TimeoutError:
            return PortInfo(port=port, state=PortState.FILTERED)
        except Exception:  # noqa: BLE001 -- Socket kann unspezifizierte Errors werfen, fail-safe None
            return None

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Versucht ein Service-Banner zu lesen.

        TLS-Ports (443/8443) werden per TLS-Handshake gefingerprintet
        (ausgehandelte Version/Cipher/ALPN) statt mit einem toten Plaintext-
        HEAD (F-B/); Plaintext-HTTP-Ports (80/8080) bekommen einen
        minimalen HEAD; andere Dienste werden nach kurzer Wartezeit gelesen.

        Args:
            sock: Verbundener Socket.
            port: Port-Nummer (bestimmt Protokoll-Hint).

        Returns:
            Erste Banner-Zeile (max. 200 Zeichen), bereinigt. NIEMALS
            Zertifikats-/Payload-Inhalte (Privacy, siehe Modul-Docstring).
        """
        try:
            sock.settimeout(_BANNER_TIMEOUT)
            if port in _TLS_PORTS:
                return self._grab_tls_banner(sock)
            if port in _HTTP_PLAIN_PORTS:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            raw = sock.recv(_MAX_BANNER_BYTES)
            # Nur erste Zeile, keine Binärdaten loggen
            first_line = raw.split(b"\n")[0].strip()
            return first_line.decode("utf-8", errors="replace")[:200]
        except (OSError, UnicodeDecodeError):
            return ""

    @staticmethod
    def _grab_tls_banner(sock: socket.socket) -> str:
        """Fingerprintet einen TLS-Dienst read-only per Handshake (F-B/).

        Liefert die ausgehandelte TLS-Version + Cipher + ALPN als Banner —
        bewusst KEINEN Zertifikats-Inhalt (Subject/CN ist personenbezogen,
        DSGVO; das Modul gibt keine Banner-Inhalte mit PII aus). Akzeptiert
        self-signed/abgelaufene Zertifikate (``CERT_NONE``), weil interne Hosts
        solche oft nutzen — wir authentifizieren nicht, wir fingerprinten
        read-only (kein HEAD/Payload gesendet; der Handshake IST der Probe).

        Args:
            sock: Bereits verbundener Klartext-Socket auf einem TLS-Port.

        Returns:
            Banner wie ``"TLSv1.3 TLS_AES_256_GCM_SHA384 h2"`` — oder leerer
            String bei Verbindungsfehler/Timeout (fail-safe).
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Reihenfolge zwingend: check_hostname VOR verify_mode=CERT_NONE
        # (sonst ValueError) — wir prüfen das Zert bewusst nicht.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:  # ALPN nicht verfügbar — unkritisch
            pass
        try:
            with context.wrap_socket(sock) as tls:
                version = tls.version() or "TLS"
                cipher = tls.cipher()
                alpn = tls.selected_alpn_protocol()
            parts = [version]
            if cipher and cipher[0]:
                parts.append(cipher[0])
            if alpn:
                parts.append(alpn)
            return " ".join(parts)[:200]
        except ssl.SSLError:
            return "TLS (Handshake fehlgeschlagen)"
        except (OSError, ValueError):
            return ""

    def _ping_host(self, host: str) -> bool:
        """Einfacher Erreichbarkeitscheck via TCP-Verbindung auf Port 80/443.

        Args:
            host: Zu prüfender Host.

        Returns:
            True wenn Host auf Port 80 oder 443 antwortet.
        """
        for port in (80, 443, 22):
            try:
                with socket.create_connection((host, port), timeout=self._timeout):
                    return True
            except OSError:
                continue
        return False
