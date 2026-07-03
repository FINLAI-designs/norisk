"""models — Domänenmodelle für den SSL/TLS-Zertifikats-Monitor.

Keine Außen-Abhängigkeiten (nur Python-Stdlib).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CertStatus(Enum):
    """Status eines überwachten Zertifikats."""

    OK = "ok"
    WARNUNG = "warnung"  # <90 Tage bis Ablauf oder TLS 1.2
    KRITISCH = "kritisch"  # <30 Tage oder selbst-signiert oder TLS <1.2
    FEHLER = "fehler"  # Verbindung nicht möglich
    UNBEKANNT = "unbekannt"  # Noch nie geprüft


@dataclass(frozen=True)
class CertInfo:
    """Vollständige Informationen zu einem TLS-Zertifikat.

    Attributes:
        domain: Überwachte Domain.
        port: TLS-Port (Standard 443).
        aussteller: Zertifikats-Aussteller (CN/O).
        gueltig_von: Gültigkeitsbeginn (ISO-String oder leer).
        gueltig_bis: Ablaufdatum (ISO-String oder leer).
        tage_verbleibend: Verbleibende Gültigkeitstage.
        tls_version: Verwendete TLS-Version (z.B. "TLSv1.3").
        cipher_name: Cipher-Suite-Name.
        cipher_bits: Schlüssellänge in Bits.
        ist_self_signed: True wenn selbst-signiert.
        san_domains: Subject Alternative Names.
        serial_number: Zertifikats-Seriennummer (hex).
        status: Berechneter Status.
        findings: Liste der erkannten Probleme.
        letzte_pruefung: Zeitstempel der letzten Prüfung (ISO-String).
        fehler_meldung: Fehlermeldung bei status=FEHLER.
    """

    domain: str
    port: int = 443
    aussteller: str = ""
    gueltig_von: str = ""
    gueltig_bis: str = ""
    tage_verbleibend: int = 0
    tls_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    ist_self_signed: bool = False
    san_domains: list[str] = field(default_factory=list)
    serial_number: str = ""
    status: CertStatus = CertStatus.UNBEKANNT
    findings: list[str] = field(default_factory=list)
    letzte_pruefung: str = ""
    fehler_meldung: str = ""

    @property
    def anzeige_domain(self) -> str:
        """Domain mit Port wenn nicht 443.

        Returns:
            Domain-String für die Anzeige.
        """
        if self.port == 443:
            return self.domain
        return f"{self.domain}:{self.port}"
