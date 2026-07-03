"""
conftest — Fixture-Factories für Security-Tests.

Erzeugt bösartige/verdächtige Test-Fixtures ausschließlich zur Testlaufzeit.
Keine echten Malware-Samples werden eingecheckt — das ist Projektrichtlinie
und vereinfacht Virenscanner-Whitelists auf Build-Agents.

Alle Fixtures schreiben in ``tmp_path`` (pytest-built-in).

Author: Patrick Riederich
"""

from __future__ import annotations

import json
import os
import struct
import zipfile
from pathlib import Path

import pytest

# Dev-Override: FINLAI_DEV=1 schaltete frueher die (mit/ entfernten)
# Lizenz-Features an. Der Import-Validator braucht das nicht mehr — der
# Deep-Content-Scan laeuft unbedingt; die Variable bleibt nur als genereller
# Dev-Schalter fuer andere Pfade.
os.environ.setdefault("FINLAI_DEV", "1")


# ---------------------------------------------------------------------------
# TXT-Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def make_txt(tmp_path: Path):
    """Factory: Legt eine UTF-8-TXT-Datei an und gibt den Pfad zurück."""

    def _make(content: str, name: str = "sample.txt") -> Path:
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        return p

    return _make


@pytest.fixture
def make_txt_bytes(tmp_path: Path):
    """Factory: Schreibt rohe Bytes in eine Datei (für UTF-8-Fehler-Tests)."""

    def _make(raw: bytes, name: str = "sample.txt") -> Path:
        p = tmp_path / name
        p.write_bytes(raw)
        return p

    return _make


# ---------------------------------------------------------------------------
# JSON-Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def make_json(tmp_path: Path):
    """Factory: Schreibt ein JSON-Dokument (Python-Objekt wird json-serialisiert)."""

    def _make(obj: object, name: str = "sample.json") -> Path:
        p = tmp_path / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    return _make


@pytest.fixture
def make_deep_json(tmp_path: Path):
    """Factory: Erzeugt ein JSON mit gegebener Verschachtelungstiefe.

    Die Struktur ist ein lineares Nest (``[[[...]]]``), damit das Ergebnis
    klein bleibt und der Depth-Scanner die Tiefe erkennt.
    """

    def _make(depth: int, name: str = "deep.json") -> Path:
        # "[" * depth + "]" * depth → lineare Liste
        payload = "[" * depth + "]" * depth
        p = tmp_path / name
        p.write_text(payload, encoding="utf-8")
        return p

    return _make


# ---------------------------------------------------------------------------
# XLSX-Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def make_xlsx(tmp_path: Path):
    """Factory: Erzeugt ein minimales XLSX mit optional platzierten Zellwerten.

    Benutzt openpyxl (bereits Projekt-Dependency). Der ``cells``-Parameter
    ist ein dict ``{"A1": "Wert",...}``.
    """

    def _make(
        cells: dict[str, str] | None = None,
        name: str = "sample.xlsx",
    ) -> Path:
        from openpyxl import Workbook  # noqa: PLC0415

        wb = Workbook()
        ws = wb.active
        ws.title = "Test"
        for coord, value in (cells or {}).items():
            ws[coord] = value
        p = tmp_path / name
        wb.save(str(p))
        wb.close()
        return p

    return _make


@pytest.fixture
def make_zip_bomb_xlsx(tmp_path: Path):
    """Factory: Synthetisches XLSX mit stark komprimierbarer Nutzlast.

    Das erzeugte ZIP enthält einen einzigen Eintrag mit ``size``-Nullbytes.
    Nullbytes erreichen typisch >1000:1 Kompressionsrate → löst
    ``XLSX_ZIP_COMPRESSION_RATIO`` aus. Ist kein gültiges XLSX (fehlt
    ``[Content_Types].xml``) — wird über die Registry aber als XLSX-Typ
    validiert; Magika erkennt ``zip`` und der Zip-Scanner greift.
    """

    def _make(size: int = 10 * 1024 * 1024, name: str = "bomb.xlsx") -> Path:
        p = tmp_path / name
        with zipfile.ZipFile(
            p, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as zf:
            zf.writestr("payload.bin", b"\x00" * size)
        return p

    return _make


@pytest.fixture
def make_many_entry_xlsx(tmp_path: Path):
    """Factory: ZIP mit vielen Einträgen (überschreitet MAX_ZIP_ENTRIES)."""

    def _make(count: int = 10_500, name: str = "many.xlsx") -> Path:
        p = tmp_path / name
        with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_STORED) as zf:
            for i in range(count):
                zf.writestr(f"entry_{i}.txt", b"x")
        return p

    return _make


@pytest.fixture
def make_external_link_xlsx(tmp_path: Path, make_xlsx):
    """Factory: XLSX + manuell eingefügte ``xl/externalLinks/*``-Einträge.

    Erzeugt zunächst ein sauberes XLSX, hängt dann einen externalLink-
    Stub in den ZIP-Container an (openpyxl selbst fügt keine externen
    Links von Hand hinzu).
    """

    def _make(name: str = "extlinks.xlsx") -> Path:
        base = make_xlsx({"A1": "Hallo"}, name=name)
        with zipfile.ZipFile(base, "a") as zf:
            zf.writestr(
                "xl/externalLinks/externalLink1.xml",
                b'<?xml version="1.0"?><externalLink/>',
            )
        return base

    return _make


# ---------------------------------------------------------------------------
# PDF-Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def make_pdf(tmp_path: Path):
    """Factory: Schreibt ein minimales, Magika-erkennbares PDF.

    Benutzt ``reportlab`` (bereits Projekt-Dependency).
    """

    def _make(name: str = "sample.pdf") -> Path:
        from reportlab.pdfgen import canvas  # noqa: PLC0415

        p = tmp_path / name
        c = canvas.Canvas(str(p))
        c.drawString(100, 750, "FINLAI test PDF")
        c.showPage()
        c.save()
        return p

    return _make


@pytest.fixture
def make_truncated_pdf(tmp_path: Path, make_pdf):
    """Factory: PDF ohne EOF-Marker (abgeschnitten)."""

    def _make(name: str = "truncated.pdf") -> Path:
        p = make_pdf(name=name)
        # Letzte 1.5 KB entfernen — löscht zuverlässig den %%EOF-Marker
        data = p.read_bytes()
        p.write_bytes(data[: max(0, len(data) - 1500)])
        return p

    return _make


@pytest.fixture
def make_headerless_pdf(tmp_path: Path):
    """Factory: Datei ohne ``%PDF-`` Header, aber mit genug Bytes für Magika."""

    def _make(name: str = "no_header.pdf") -> Path:
        p = tmp_path / name
        # Kein %PDF- aber Größe > 0
        p.write_bytes(b"NOT A PDF" * 100)
        return p

    return _make


@pytest.fixture
def make_pdf_with_raw(tmp_path: Path):
    """Factory: Minimales, handgeschriebenes PDF mit beliebigen Katalog-Keys.

    Handcraft statt reportlab/pypdf-Write, weil ältere pypdf-Versionen
    z. B. ``/OpenAction`` per API nicht sauber setzen. Das Ergebnis ist
    ein gültiges 1.5er-PDF, das pypdf lesen kann.
    """

    def _make(
        catalog_extra: str = "", extra_objects: str = "", name: str = "t.pdf"
    ) -> Path:
        header = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
        catalog = (
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R"
            + catalog_extra.encode("latin-1")
            + b" >>\nendobj\n"
        )
        pages = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        page = (
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] "
            b">>\nendobj\n"
        )
        extra = extra_objects.encode("latin-1")

        body = catalog + pages + page + extra
        offset = len(header)
        xref_entries = [b"0000000000 65535 f \n"]
        pos = offset
        for obj_bytes in (catalog, pages, page):
            xref_entries.append(f"{pos:010d} 00000 n \n".encode("latin-1"))
            pos += len(obj_bytes)
        for _ in range(extra_objects.count("endobj")):
            xref_entries.append(f"{pos:010d} 00000 n \n".encode("latin-1"))

        xref_offset = offset + len(body)
        total_objs = 4 + extra_objects.count("endobj")
        xref = f"xref\n0 {total_objs}\n".encode("latin-1") + b"".join(xref_entries)
        trailer = (
            f"trailer\n<< /Size {total_objs} /Root 1 0 R >>\nstartxref\n"
            f"{xref_offset}\n%%EOF\n"
        ).encode("latin-1")

        p = tmp_path / name
        p.write_bytes(header + body + xref + trailer)
        return p

    return _make


# ---------------------------------------------------------------------------
# Binary-Fixture (für Type-Spoofing)
# ---------------------------------------------------------------------------


@pytest.fixture
def make_fake_binary(tmp_path: Path):
    """Factory: Schreibt ein Dummy-PE (Windows-Executable-Header).

    Magika erkennt den MZ-Header und liefert Label ``pebin``. Die
    Umbenennung auf ``.pdf``/``.xlsx`` usw. löst TYPE_SPOOFING_DANGEROUS aus.
    """

    def _make(name: str = "fake.pdf") -> Path:
        p = tmp_path / name
        # Minimal-PE: MZ + e_lfanew + PE\0\0 (erkannt als pebin)
        mz_stub = b"MZ" + bytes(58) + struct.pack("<I", 64)
        pe_stub = b"PE\x00\x00"
        # Polstern, damit Magika genug Inhalt hat
        padding = bytes(4096)
        p.write_bytes(mz_stub + pe_stub + padding)
        return p

    return _make
