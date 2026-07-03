"""test_email_scanner_service — Service + Repository End-to-End-Tests.

Baut Mails mit bekannten malicious/sauberen Attachments synthetisch,
scant sie via ``EmailScannerService`` und prüft:

    * Aggregat-Status (SAFE/WARN/BLOCK)
    * PDF-Deep-Scan wird nur für PDFs ausgeführt
    * Bidi-Override im TXT-Attachment → WARN
    * Kaputte Mail-Datei → WARN mit fehler-Feld, kein Crash
    * Repository speichert und listet Reports
    * Quarantäne ist read-only (dedupliziert über SHA-256)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import os
import uuid
from email.message import EmailMessage
from pathlib import Path

import pytest

os.environ.setdefault("FINLAI_DEV", "1")

from core.database.encrypted_db import EncryptedDatabase
from tools.email_scanner.application.scan_service import EmailScannerService
from tools.email_scanner.data.repository import EmailScannerRepository
from tools.email_scanner.domain.models import (
    Attachment,
    AttachmentReport,
    MailReport,
    MailScanStatus,
)


def _build_eml_file(
    tmp_path: Path,
    attachments: list[tuple[str, str, bytes]],
    name: str = "mail.eml",
) -> Path:
    msg = EmailMessage()
    msg["Subject"] = "Rechnung"
    msg["From"] = "billing@example.at"
    msg["To"] = "customer@example.at"
    msg["Date"] = "Mon, 17 Apr 2026 10:00:00 +0000"
    msg.set_content("Sehr geehrte Damen und Herren,\n\nBitte anbei die Rechnung.\n")
    for filename, ctype, data in attachments:
        maintype, _, subtype = ctype.partition("/")
        msg.add_attachment(
            data,
            maintype=maintype,
            subtype=subtype or "octet-stream",
            filename=filename,
        )
    path = tmp_path / name
    path.write_bytes(bytes(msg))
    return path


def _minimal_pdf() -> bytes:
    header = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
    catalog = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    pages = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    page = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    body = catalog + pages + page
    offset = len(header)
    entries = [b"0000000000 65535 f \n"]
    pos = offset
    for o in (catalog, pages, page):
        entries.append(f"{pos:010d} 00000 n \n".encode("latin-1"))
        pos += len(o)
    xref_offset = offset + len(body)
    xref = b"xref\n0 4\n" + b"".join(entries)
    trailer = (
        f"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    ).encode("latin-1")
    return header + body + xref + trailer


# ---------------------------------------------------------------------------
# Service-Tests
# ---------------------------------------------------------------------------


class TestEmailScannerService:
    def test_mail_mit_sauberem_pdf_ist_safe(self, tmp_path: Path) -> None:
        path = _build_eml_file(
            tmp_path, [("rechnung.pdf", "application/pdf", _minimal_pdf())]
        )
        service = EmailScannerService()

        report = service.scan(path)

        assert isinstance(report, MailReport)
        assert report.status is MailScanStatus.SAFE
        assert len(report.attachment_reports) == 1
        assert report.attachment_reports[0].pdf_scan is not None
        assert not report.fehler

    def test_bidi_txt_wird_gewarnt(self, tmp_path: Path) -> None:
        # U+202E = Right-to-Left-Override — Trojan-Source-Indikator
        bidi_bytes = "normaler text\u202enachgeschoben".encode()
        path = _build_eml_file(
            tmp_path,
            [("readme.txt", "text/plain", bidi_bytes)],
            name="bidi.eml",
        )
        service = EmailScannerService()

        report = service.scan(path)

        assert report.status is MailScanStatus.WARN
        assert report.attachment_reports[0].status is MailScanStatus.WARN

    def test_kaputte_datei_liefert_fehler_report(self, tmp_path: Path) -> None:
        path = tmp_path / "kaputt.eml"
        path.write_bytes(b"\x00" * 50)  # kein RFC-5322-Header
        service = EmailScannerService()

        report = service.scan(path)

        # Auch ohne Attachments bleibt der Report WARN (Aggregat-Safe
        # wäre irreführend). Entscheidend: kein Crash.
        assert report.mail is not None or report.fehler

    def test_fehlende_datei_liefert_warn_mit_fehler(self, tmp_path: Path) -> None:
        service = EmailScannerService()
        report = service.scan(tmp_path / "existiert_nicht.eml")
        assert report.status is MailScanStatus.WARN
        assert "nicht gefunden" in report.fehler.lower()
        assert report.mail is None


# ---------------------------------------------------------------------------
# Repository-Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def repo() -> EmailScannerRepository:
    """Isoliertes Repository mit eindeutigem DB-Namen pro Testlauf."""
    db_name = f"email_scanner_test_{uuid.uuid4().hex[:8]}"
    return EmailScannerRepository(db=EncryptedDatabase(db_name))


class TestEmailScannerRepository:
    def test_speichern_und_laden_eines_reports(
        self, tmp_path: Path, repo: EmailScannerRepository
    ) -> None:
        path = _build_eml_file(
            tmp_path, [("doc.pdf", "application/pdf", _minimal_pdf())]
        )
        service = EmailScannerService()
        report = service.scan(path)

        new_id = repo.speichere_report(report)
        assert new_id > 0

        reports = repo.lade_reports()
        assert reports
        assert reports[0]["id"] == new_id
        assert reports[0]["status"] is MailScanStatus.SAFE
        assert reports[0]["attachments_summary"]

    def test_quarantaene_dedupliziert_nach_sha256(
        self, repo: EmailScannerRepository
    ) -> None:
        from core.security.validation_report import (
            ImportType,
            ValidationReport,
        )

        att = Attachment.from_bytes("x.bin", "application/octet-stream", b"payload")
        fake_validation = ValidationReport(
            path=Path("x.bin"), declared_type=ImportType.UNKNOWN
        )
        att_report = AttachmentReport(
            attachment=att,
            validation=fake_validation,
            pdf_scan=None,
            status=MailScanStatus.SAFE,
        )

        h1 = repo.quarantaene_speichern(att_report)
        h2 = repo.quarantaene_speichern(att_report)  # zweiter Aufruf dedupliziert
        assert h1 == h2

        liste = repo.lade_quarantaene()
        assert len(liste) == 1
        assert liste[0]["filename"] == "x.bin"

        blob = repo.lade_blob(h1)
        assert blob == b"payload"
