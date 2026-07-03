"""cert_scanner — SSL/TLS-Verbindung + Zertifikat-Extraktion.

Nutzt ausschließlich Python-Stdlib (ssl + socket) — keine externen Dependencies.

Schichtzugehörigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import replace
from datetime import UTC, datetime

from core.logger import get_logger
from tools.cert_monitor.domain.cert_analyzer import (
    analysiere_zertifikat,
    berechne_tage_verbleibend,
)
from tools.cert_monitor.domain.models import CertInfo, CertStatus

_log = get_logger(__name__)

_TIMEOUT_S = 10


class CertScanner:
    """Stellt SSL-Verbindung her und extrahiert Zertifikatsdaten.

    Nutzt Python-Stdlib ssl + socket — keine externen Dependencies.
    """

    def scan(self, domain: str, port: int = 443) -> CertInfo:
        """Verbindet sich mit dem Host und extrahiert Zertifikatsdaten.

        Args:
            domain: Hostname (ohne https://).
            port: TLS-Port (Standard 443).

        Returns:
            CertInfo mit ausgefüllten Zertifikatsdaten und berechneter Status/Findings.
        """
        cert = CertInfo(
            domain=domain,
            port=port,
            letzte_pruefung=datetime.now(tz=UTC).isoformat(),
        )
        try:
            ctx = ssl.create_default_context()
            with (
                socket.create_connection((domain, port), timeout=_TIMEOUT_S) as sock,
                ctx.wrap_socket(sock, server_hostname=domain) as ssock,
            ):
                raw_cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version() or ""
                cert = self._parse_cert(cert, raw_cert, cipher, tls_version)
        except ssl.SSLCertVerificationError:
            # Manche Self-Signed können wir trotzdem auslesen
            cert = self._scan_unverified(domain, port, cert)
        except (OSError, TimeoutError) as exc:
            cert = replace(cert, status=CertStatus.FEHLER, fehler_meldung=str(exc))
            _log.warning(
                "CertScanner: Verbindungsfehler für %s:%d — %s", domain, port, exc
            )
        except Exception as exc:  # noqa: BLE001 — Scan darf nie crashen, nur FEHLER setzen
            cert = replace(
                cert,
                status=CertStatus.FEHLER,
                fehler_meldung=f"Unerwarteter Fehler: {exc}",
            )
            _log.exception("CertScanner: Fehler für %s:%d", domain, port)

        return analysiere_zertifikat(cert)

    def _scan_unverified(self, domain: str, port: int, cert: CertInfo) -> CertInfo:
        """Scan mit deaktivierter Verifikation — für Self-Signed Zertifikate.

        Args:
            domain: Hostname.
            port: Port.
            cert: Teilweise befülltes CertInfo.

        Returns:
            CertInfo mit Self-Signed-Flag und verfügbaren Daten.
        """
        try:
            ctx = ssl._create_unverified_context()  # noqa: SLF001, S323 # nosec B323
            with (
                socket.create_connection((domain, port), timeout=_TIMEOUT_S) as sock,
                ctx.wrap_socket(sock, server_hostname=domain) as ssock,
            ):
                raw_cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version() or ""
                cert = self._parse_cert(cert, raw_cert, cipher, tls_version)
                cert = replace(cert, ist_self_signed=True)
        except Exception as exc:  # noqa: BLE001 — Scan darf nie crashen, nur FEHLER setzen
            _log.warning(
                "CertScanner: Unverified-Scan für %s:%d fehlgeschlagen — %s",
                domain,
                port,
                exc,
            )
            cert = replace(cert, status=CertStatus.FEHLER, fehler_meldung=str(exc))
        return cert

    def _parse_cert(
        self,
        cert: CertInfo,
        raw_cert: dict,
        cipher: tuple | None,
        tls_version: str,
    ) -> CertInfo:
        """Extrahiert Felder aus dem ssl.getpeercert-Dict.

        ``CertInfo`` ist frozen (R16) — die uebergebene Instanz wird NICHT
        mutiert, sondern dient als Vorlage; das Ergebnis entsteht via
:func:`dataclasses.replace`.

        Args:
            cert: Basis-CertInfo (frozen, Vorlage; wird nicht mutiert).
            raw_cert: Rohdaten aus ssl.getpeercert.
            cipher: Cipher-Tuple aus ssock.cipher.
            tls_version: TLS-Versions-String aus ssock.version.

        Returns:
            Neues CertInfo mit den extrahierten Feldern (Kopie via replace).
        """
        # CertInfo ist frozen (R16) — Felder sammeln und EINMAL via replace setzen
        # (keine Attribut-Mutation, sonst FrozenInstanceError →).
        updates: dict[str, object] = {}

        # Aussteller
        issuer_dict = dict(x[0] for x in raw_cert.get("issuer", []))
        updates["aussteller"] = issuer_dict.get("organizationName") or issuer_dict.get(
            "commonName", "—"
        )

        # Self-Signed: Issuer == Subject
        subject_dict = dict(x[0] for x in raw_cert.get("subject", []))
        if issuer_dict == subject_dict:
            updates["ist_self_signed"] = True

        # Ablauf
        not_after = raw_cert.get("notAfter", "")
        not_before = raw_cert.get("notBefore", "")
        updates["gueltig_bis"] = not_after
        updates["gueltig_von"] = not_before
        updates["tage_verbleibend"] = berechne_tage_verbleibend(not_after)

        # TLS + Cipher
        updates["tls_version"] = tls_version
        if cipher:
            updates["cipher_name"] = cipher[0] or ""
            updates["cipher_bits"] = cipher[2] or 0

        # SAN
        san_list = raw_cert.get("subjectAltName", [])
        updates["san_domains"] = [v for t, v in san_list if t == "DNS"]

        # Serial
        updates["serial_number"] = str(raw_cert.get("serialNumber", ""))

        return replace(cert, **updates)
