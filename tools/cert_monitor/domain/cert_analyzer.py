"""cert_analyzer — Zertifikats-Analyse und Status-Berechnung.

Analysiert ein CertInfo-Objekt und berechnet Status + Findings.
Keine Netzwerk-I/O (die SSL-Verbindung ist in data/cert_scanner.py).

Keine Außen-Abhängigkeiten (nur Python-Stdlib).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import replace

from tools.cert_monitor.domain.models import CertInfo, CertStatus

# Schwellenwerte für Ablauf-Warnungen
_TAGE_KRITISCH = 30
_TAGE_WARNUNG = 90

# TLS-Versionen und ihre Bewertung
_TLS_KRITISCH = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
_TLS_WARNUNG = {"TLSv1.2"}
_TLS_OK = {"TLSv1.3"}

# Minimale Cipher-Bitlänge
_CIPHER_BITS_KRITISCH = 128


def analysiere_zertifikat(cert: CertInfo) -> CertInfo:
    """Analysiert ein CertInfo und befüllt status + findings.

    ``CertInfo`` ist frozen (R16) — die übergebene Instanz wird NICHT mutiert;
    das Ergebnis entsteht via:func:`dataclasses.replace`.

    Args:
        cert: CertInfo-Objekt mit den SSL-Rohdaten (aus cert_scanner).

    Returns:
        Neues CertInfo mit ausgefülltem status und findings (Kopie via replace).
    """
    if cert.status == CertStatus.FEHLER:
        return cert

    findings: list[str] = []
    status = CertStatus.OK

    # ── Ablauf-Prüfung ──────────────────────────────────────────────────
    if cert.tage_verbleibend <= 0:
        findings.append("[KRITISCH] Zertifikat ist abgelaufen!")
        status = CertStatus.KRITISCH
    elif cert.tage_verbleibend <= _TAGE_KRITISCH:
        findings.append(
            f"[KRITISCH] Zertifikat läuft in {cert.tage_verbleibend} Tag(en) ab!"
        )
        status = CertStatus.KRITISCH
    elif cert.tage_verbleibend <= _TAGE_WARNUNG:
        findings.append(
            f"[WARNUNG] Zertifikat läuft in {cert.tage_verbleibend} Tagen ab"
        )
        if status == CertStatus.OK:
            status = CertStatus.WARNUNG

    # ── Self-Signed ─────────────────────────────────────────────────────
    if cert.ist_self_signed:
        findings.append(
            "[WARNUNG] Selbst-signiertes Zertifikat — Browser zeigen Warnung"
        )
        if status == CertStatus.OK:
            status = CertStatus.WARNUNG

    # ── TLS-Version ─────────────────────────────────────────────────────
    if cert.tls_version in _TLS_KRITISCH:
        findings.append(
            f"[KRITISCH] Veraltete TLS-Version: {cert.tls_version} — sofort auf TLS 1.3 aktualisieren"
        )
        status = CertStatus.KRITISCH
    elif cert.tls_version in _TLS_WARNUNG:
        findings.append("[WARNUNG] TLS 1.2 — TLS 1.3 wird empfohlen")
        if status == CertStatus.OK:
            status = CertStatus.WARNUNG

    # ── Cipher-Stärke ───────────────────────────────────────────────────
    if 0 < cert.cipher_bits < _CIPHER_BITS_KRITISCH:
        findings.append(
            f"[KRITISCH] Schwache Cipher-Stärke: {cert.cipher_bits} Bit (mindestens 128 Bit erforderlich)"
        )
        status = CertStatus.KRITISCH

    return replace(cert, findings=findings, status=status)


def berechne_tage_verbleibend(gueltig_bis_iso: str) -> int:
    """Berechnet die verbleibenden Gültigkeitstage.

    Args:
        gueltig_bis_iso: Ablaufdatum im ISO-Format (YYYY-MM-DD HH:MM:SS oder YYYY-MM-DD).

    Returns:
        Verbleibende Tage (kann negativ sein bei abgelaufenen Zertifikaten).
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    if not gueltig_bis_iso:
        return 0

    formate = [
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S %Y %Z",
        "%Y-%m-%d",
    ]
    ablauf_dt: datetime | None = None
    for fmt in formate:
        try:
            ablauf_dt = datetime.strptime(gueltig_bis_iso, fmt)
            if ablauf_dt.tzinfo is None:
                ablauf_dt = ablauf_dt.replace(tzinfo=UTC)
            break
        except ValueError:
            continue

    if ablauf_dt is None:
        return 0

    delta = ablauf_dt - datetime.now(tz=UTC)
    return delta.days
