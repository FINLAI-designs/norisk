"""
models — Domain-Modelle für den E-Mail-Anhang-Scanner.

Die Modelle repräsentieren:

- ``Attachment``: Rohdaten eines E-Mail-Anhangs (Dateiname, MIME-Type,
  Bytes) — unabhängig vom Transport-Format (.eml/.msg).
- ``ParsedMail``: Geparste E-Mail mit Metadaten, Plaintext-Body und
  Attachment-Liste. Enthält niemals ausführbaren HTML-Content — der
  HTML-Body wird nur als Quelltext weitergereicht, nie gerendert.
- ``AttachmentReport``: Ergebnis der Anhang-Validierung (Report des
  Secure Import Validators, optional Ergebnis des PDF-Risk-Scanners).
- ``MailReport``: Aggregat-Ergebnis einer Mail mit allen Anhang-Reports.
- ``MailScanStatus``: Tabellen-Status (safe/warn/block).

Es gibt bewusst keinen Konstruktor für ``Attachment.bytes`` aus einem
Pfad — Anhänge kommen nur aus dem Parser, niemals vom Dateisystem.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from core.security.validation_report import Severity, ValidationReport
from tools.pdf_risk_scanner.domain.models import PdfScanResult


class MailScanStatus(Enum):
    """Gesamt-Status einer Mail in der Tabelle."""

    SAFE = "safe"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class Attachment:
    """Roh-Attachment einer E-Mail.

    Attributes:
        filename: Dateiname aus dem MIME- oder MSG-Header (ggf. leer).
        content_type: ``Content-Type`` laut Header (z. B.
            ``application/pdf``). Bei.msg extrapoliert aus
            ``extension``.
        size: Größe in Bytes (``len(data)``).
        data: Der eigentliche Inhalt.
        sha256: Hex-SHA-256 des Inhalts — als stabiler Identifier
            (z. B. für externe Analyse / Weiterleitung).
    """

    filename: str
    content_type: str
    size: int
    data: bytes
    sha256: str

    @classmethod
    def from_bytes(cls, filename: str, content_type: str, data: bytes) -> Attachment:
        """Erstellt ein Attachment und berechnet den SHA-256-Hash.

        Args:
            filename: Dateiname.
            content_type: MIME-Type.
            data: Rohdaten.

        Returns:
            Neues ``Attachment``-Objekt.
        """
        return cls(
            filename=filename or "(ohne Namen)",
            content_type=content_type or "application/octet-stream",
            size=len(data),
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
        )


@dataclass(frozen=True)
class ParsedMail:
    """Geparste E-Mail mit Metadaten und Attachments.

    Attributes:
        subject: Betreff.
        from_addr: Absenderadresse (roh, keine Validierung).
        to_addrs: Liste der Empfänger.
        date: Datum aus dem Header (best-effort, sonst ``None``).
        body_text: Plaintext-Body (niemals HTML).
        body_html_source: HTML-Body als **Quelltext** (ungerendert).
        attachments: Liste der Top-Level-Anhänge.
        nested_mails: Rekursiv geparste ``message/rfc822``-Mails.
        tiefe: Aktuelle Verschachtelungs-Tiefe (0 = Top-Level).
    """

    subject: str
    from_addr: str
    to_addrs: list[str]
    date: datetime | None
    body_text: str
    body_html_source: str
    attachments: list[Attachment] = field(default_factory=list)
    nested_mails: list[ParsedMail] = field(default_factory=list)
    tiefe: int = 0


@dataclass(frozen=True)
class AttachmentReport:
    """Ergebnis der Analyse eines einzelnen Anhangs.

    Attributes:
        attachment: Ursprüngliches Attachment.
        validation: Report des Secure Import Validators.
        pdf_scan: Nur bei PDFs: Ergebnis des Tiefen-Scans.
        status: Tabellen-Status aggregiert (SAFE/WARN/BLOCK).
    """

    attachment: Attachment
    validation: ValidationReport
    pdf_scan: PdfScanResult | None
    status: MailScanStatus


@dataclass(frozen=True)
class MailReport:
    """Aggregat-Ergebnis einer gescannten E-Mail.

    Attributes:
        source_path: Pfad der ursprünglichen.eml/.msg-Datei.
        mail: Geparste Mail (Metadaten, Bodies, Attachments).
        attachment_reports: Einzel-Reports aller Top-Level-Anhänge.
        nested_reports: Rekursive Reports aus ``message/rfc822``-Mails.
        status: Höchste Eskalationsstufe aller Reports.
        risk_score: Max-Score über alle Attachment-Validierungen
            (0–100).
        fehler: Optionale Fehlermeldung, falls Parsing abgebrochen
            wurde (Mail bleibt mit Status WARN gelistet).
    """

    source_path: str
    mail: ParsedMail | None
    attachment_reports: list[AttachmentReport] = field(default_factory=list)
    nested_reports: list[MailReport] = field(default_factory=list)
    status: MailScanStatus = MailScanStatus.SAFE
    risk_score: int = 0
    fehler: str = ""


def status_from_validation(
    validation: ValidationReport, pdf_scan: PdfScanResult | None
) -> MailScanStatus:
    """Bildet Validation-Report und optionalen PDF-Scan auf ``MailScanStatus`` ab.

    Args:
        validation: Secure-Import-Validator-Report des Attachments.
        pdf_scan: Optionales Ergebnis des PDF-Risk-Scanners.

    Returns:
        ``BLOCK`` bei nicht-parsebaren Reports oder PDF-Scan-Block,
        ``WARN`` bei HIGH-Funden ODER unvollständiger Inspektion (Fail-Closed,
), sonst ``SAFE``.
    """
    if not validation.safe_to_parse:
        return MailScanStatus.BLOCK
    if pdf_scan is not None and not pdf_scan.report.safe_to_parse:
        return MailScanStatus.BLOCK
    if validation.has_severity(Severity.HIGH):
        return MailScanStatus.WARN
    if pdf_scan is not None and pdf_scan.report.has_severity(Severity.HIGH):
        return MailScanStatus.WARN
    # Fail-Closed: konnte der Anhang (oder sein eingebettetes PDF) nicht
    # vollständig geprüft werden, nie „sicher" melden.
    if validation.scan_incomplete():
        return MailScanStatus.WARN
    if pdf_scan is not None and pdf_scan.report.scan_incomplete():
        return MailScanStatus.WARN
    return MailScanStatus.SAFE


def aggregate_status(reports: list[AttachmentReport]) -> MailScanStatus:
    """Aggregiert den schwersten Status einer Liste von Attachment-Reports.

    Args:
        reports: Einzel-Reports.

    Returns:
        ``BLOCK`` wenn irgendein Report blockt, ``WARN`` wenn mindestens
        ein WARN vorliegt, sonst ``SAFE`` (auch bei leerer Liste).
    """
    if any(r.status is MailScanStatus.BLOCK for r in reports):
        return MailScanStatus.BLOCK
    if any(r.status is MailScanStatus.WARN for r in reports):
        return MailScanStatus.WARN
    return MailScanStatus.SAFE
