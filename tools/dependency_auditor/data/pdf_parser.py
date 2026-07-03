"""
pdf_parser — Extrahiert Package-Listen aus maschinenlesbaren PDF-Dateien.

Verwendet pdfplumber fuer Text-Extraktion. Funktioniert nur bei
digitalen PDFs (kein OCR fuer gescannte Dokumente).

Nach der Text-Extraktion werden die Zeilen wie eine requirements.txt
geparst (gleiche Logik wie requirements_parser.py).

Sicherheit:
  - Dateipfad wird ueber validate_file_path geprueft (Path-Traversal-Schutz)
  - Nur.pdf Dateien erlaubt
  - Max 200 Seiten — Schutz vor sehr grossen Dateien

Schichtzugehoerigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.exceptions import ValidationError
from core.security.validators import validate_file_path
from tools.dependency_auditor.data.requirements_parser import _parse_line
from tools.dependency_auditor.domain.models import DependencyInfo

_MAX_PAGES = 200


def parse_pdf_dependencies(file_path: str) -> list[DependencyInfo]:
    """Extrahiert Package-Informationen aus einer PDF-Datei.

    Parst den extrahierten Text zeilenweise wie eine requirements.txt.

    Args:
        file_path: Pfad zur.pdf-Datei (wird validiert).

    Returns:
        Liste der geparsten DependencyInfo-Objekte.

    Raises:
        ValueError: Wenn der Pfad ungueltig oder kein Text extrahierbar.
        FileNotFoundError: Wenn die Datei nicht existiert.
        RuntimeError: Wenn pdfplumber nicht installiert ist.
    """
    try:
        import pdfplumber  # noqa: PLC0415
    except ImportError as exc:
        raise ValidationError(
            "pdfplumber nicht installiert — pip install pdfplumber"
        ) from exc

    validated = validate_file_path(file_path, ["pdf"])

    lines: list[str] = []
    with pdfplumber.open(validated) as pdf:
        pages = pdf.pages[:_MAX_PAGES]
        for page in pages:
            text = page.extract_text()
            if text:
                lines.extend(text.splitlines())

    if not lines:
        raise ValidationError(
            "Keine Textdaten im PDF gefunden. "
            "Nur maschinenlesbare PDFs werden unterstützt (kein Scan/OCR)."
        )

    result: list[DependencyInfo] = []
    for global_line_no, raw_line in enumerate(lines, start=1):
        dep = _parse_line(raw_line, global_line_no)
        if dep is not None:
            result.append(dep)

    return result
