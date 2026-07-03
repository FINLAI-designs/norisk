"""test_email_scanner_parsers — Parser + Attachment-Router-Tests.

Deckt:
    * EML-Parser mit Plaintext + HTML + Attachments
    * EML mit verschachtelter message/rfc822
    * Größen-Limit
    * Attachment-Router: PDF-Routing + Deep-Scan, Nicht-PDF, Unknown
    * Mime/Suffix-basiertes Type-Guessing

MSG-Parser wird in einem separaten Modul abgedeckt, sobald echte
MSG-Fixtures verfügbar sind — das extract-msg-Modul unterstützt
keinen trivialen Synthese-Constructor.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import os
from email.message import EmailMessage
from pathlib import Path

import pytest

os.environ.setdefault("FINLAI_DEV", "1")

from core.security import ImportType
from tools.email_scanner.application.attachment_router import (
    AttachmentRouter,
    _guess_import_type,
)
from tools.email_scanner.application.parsers.eml_parser import (
    EmlParseError,
    parse_eml,
)
from tools.email_scanner.domain.models import Attachment, MailScanStatus

# ---------------------------------------------------------------------------
# EML-Fixture-Helper
# ---------------------------------------------------------------------------


def _build_eml(
    tmp_path: Path,
    *,
    subject: str = "Test",
    body_text: str = "Hallo Welt",
    body_html: str | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
    nested: EmailMessage | None = None,
    name: str = "mail.eml",
) -> Path:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "alice@example.at"
    msg["To"] = "bob@example.at"
    msg["Date"] = "Mon, 17 Apr 2026 10:00:00 +0000"
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    for filename, ctype, data in attachments or []:
        maintype, _, subtype = ctype.partition("/")
        msg.add_attachment(
            data,
            maintype=maintype,
            subtype=subtype or "octet-stream",
            filename=filename,
        )

    if nested is not None:
        msg.add_attachment(nested, subtype="rfc822")

    path = tmp_path / name
    path.write_bytes(bytes(msg))
    return path


def _build_minimal_pdf() -> bytes:
    """Minimales, gültiges PDF — wird vom PDF-Scanner gelesen."""
    header = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
    catalog = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    pages = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    page = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    body = catalog + pages + page
    offset = len(header)
    xref_entries = [b"0000000000 65535 f \n"]
    pos = offset
    for obj in (catalog, pages, page):
        xref_entries.append(f"{pos:010d} 00000 n \n".encode("latin-1"))
        pos += len(obj)
    xref_offset = offset + len(body)
    xref = b"xref\n0 4\n" + b"".join(xref_entries)
    trailer = (
        f"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    ).encode("latin-1")
    return header + body + xref + trailer


# ---------------------------------------------------------------------------
# EML-Parser-Tests
# ---------------------------------------------------------------------------


class TestParseEml:
    def test_metadaten_werden_gelesen(self, tmp_path: Path) -> None:
        path = _build_eml(tmp_path, subject="Hallo", body_text="Inhalt")
        mail = parse_eml(path)
        assert mail.subject == "Hallo"
        assert mail.from_addr.endswith("alice@example.at")
        assert "bob@example.at" in mail.to_addrs
        assert "Inhalt" in mail.body_text
        assert mail.date is not None

    def test_html_bleibt_quelltext(self, tmp_path: Path) -> None:
        path = _build_eml(
            tmp_path,
            body_text="plain",
            body_html="<b>hi</b>",
        )
        mail = parse_eml(path)
        assert "<b>hi</b>" in mail.body_html_source
        assert "<b>" not in mail.body_text

    def test_attachments_werden_extrahiert(self, tmp_path: Path) -> None:
        path = _build_eml(
            tmp_path,
            attachments=[("notes.txt", "text/plain", b"hello")],
        )
        mail = parse_eml(path)
        assert len(mail.attachments) == 1
        att = mail.attachments[0]
        assert att.filename == "notes.txt"
        assert att.data == b"hello"
        assert att.size == 5
        assert att.content_type.startswith("text/plain")

    def test_nested_rfc822_wird_rekursiv_geparst(self, tmp_path: Path) -> None:
        inner = EmailMessage()
        inner["Subject"] = "Inner"
        inner["From"] = "carol@example.at"
        inner["To"] = "dave@example.at"
        inner.set_content("inner body")

        path = _build_eml(tmp_path, nested=inner, name="outer.eml")
        mail = parse_eml(path)
        assert len(mail.nested_mails) == 1
        assert mail.nested_mails[0].subject == "Inner"
        assert mail.nested_mails[0].tiefe == 1

    def test_groesse_ueber_limit_wirft_fehler(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _build_eml(tmp_path)
        monkeypatch.setattr(
            "tools.email_scanner.application.parsers.eml_parser.MAX_EML_SIZE_BYTES",
            10,
        )
        with pytest.raises(EmlParseError):
            parse_eml(path)

    def test_fehlende_datei_wirft_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            parse_eml(tmp_path / "existiert_nicht.eml")


# ---------------------------------------------------------------------------
# Router-Tests
# ---------------------------------------------------------------------------


class TestGuessImportType:
    def test_pdf_via_mime(self) -> None:
        a = Attachment.from_bytes("x.pdf", "application/pdf", b"")
        assert _guess_import_type(a) is ImportType.PDF

    def test_xlsx_via_mime(self) -> None:
        a = Attachment.from_bytes(
            "x.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            b"",
        )
        assert _guess_import_type(a) is ImportType.XLSX

    def test_suffix_fallback(self) -> None:
        a = Attachment.from_bytes("foo.json", "application/octet-stream", b"")
        assert _guess_import_type(a) is ImportType.JSON

    def test_unknown_fallback(self) -> None:
        a = Attachment.from_bytes("foo.bin", "application/octet-stream", b"")
        assert _guess_import_type(a) is ImportType.UNKNOWN


class TestAttachmentRouter:
    def test_pdf_wird_tief_gescannt(self) -> None:
        pdf_bytes = _build_minimal_pdf()
        attachment = Attachment.from_bytes("clean.pdf", "application/pdf", pdf_bytes)
        router = AttachmentRouter()

        report = router.route(attachment)

        assert report.pdf_scan is not None
        assert report.status is MailScanStatus.SAFE
        assert report.validation.declared_type is ImportType.PDF

    def test_txt_hat_keinen_pdf_scan(self) -> None:
        attachment = Attachment.from_bytes("notes.txt", "text/plain", b"hi")
        router = AttachmentRouter()

        report = router.route(attachment)

        assert report.pdf_scan is None
        assert report.validation.declared_type is ImportType.TXT

    def test_unknown_blockt_nicht(self) -> None:
        attachment = Attachment.from_bytes(
            "foo.bin", "application/octet-stream", b"\x00\x01\x02"
        )
        router = AttachmentRouter()

        report = router.route(attachment)

        assert report.status in {MailScanStatus.SAFE, MailScanStatus.WARN}
