"""
file_parser — Format-Dispatcher fuer den Dependency-Auditor-Import.

Erkennt das Dateiformat anhand der Dateiendung und leitet an den
passenden Parser weiter:
.txt /.pip → requirements_parser.parse_requirements
.json → json_parser.parse_json_dependencies
.xlsx → xlsx_parser.parse_xlsx_dependencies
.pdf → pdf_parser.parse_pdf_dependencies

Sicherheit:
  - Jeder Einzel-Parser validiert den Pfad separat (Path-Traversal-Schutz)

Schichtzugehoerigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from core.exceptions import ValidationError
from tools.dependency_auditor.domain.models import DependencyInfo

_SUPPORTED = {".txt", ".pip", ".json", ".xlsx", ".pdf"}


def parse_dependency_file(file_path: str) -> list[DependencyInfo]:
    """Parst eine Datei beliebigen Formats in DependencyInfo-Objekte.

    Erkennt das Format anhand der Dateiendung und delegiert an den
    entsprechenden Parser.

    Args:
        file_path: Pfad zur Eingabe-Datei.

    Returns:
        Liste der geparsten DependencyInfo-Objekte.

    Raises:
        ValueError: Bei nicht unterstuetzter Dateiendung oder
                    Parser-Fehler.
        FileNotFoundError: Wenn die Datei nicht existiert.
        RuntimeError: Wenn eine optionale Abhaengigkeit fehlt
                      (openpyxl fuer xlsx, pdfplumber fuer pdf).
    """
    suffix = Path(file_path).suffix.lower()

    if suffix not in _SUPPORTED:
        raise ValidationError(
            f"Nicht unterstütztes Dateiformat: {suffix!r}. "
            f"Unterstützt: {', '.join(sorted(_SUPPORTED))}"
        )

    if suffix in {".txt", ".pip"}:
        from tools.dependency_auditor.data.requirements_parser import (  # noqa: PLC0415
            parse_requirements,
        )

        return parse_requirements(file_path)

    if suffix == ".json":
        from tools.dependency_auditor.data.json_parser import (  # noqa: PLC0415
            parse_json_dependencies,
        )

        return parse_json_dependencies(file_path)

    if suffix == ".xlsx":
        from tools.dependency_auditor.data.xlsx_parser import (  # noqa: PLC0415
            parse_xlsx_dependencies,
        )

        return parse_xlsx_dependencies(file_path)

    #.pdf
    from tools.dependency_auditor.data.pdf_parser import (  # noqa: PLC0415
        parse_pdf_dependencies,
    )

    return parse_pdf_dependencies(file_path)


def supported_extensions() -> list[str]:
    """Gibt die unterstuetzten Dateiendungen zurueck.

    Returns:
        Sortierte Liste der Endungen (ohne Punkt), z. B. ``["json", "pdf",...]``.
    """
    return sorted(s.lstrip(".") for s in _SUPPORTED)
