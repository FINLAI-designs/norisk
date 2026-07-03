"""
xlsx_parser — Parst Excel-Dateien (.xlsx) mit Package-Listen.

Erkennt automatisch Spalten anhand gaengiger Header-Namen (case-insensitive):
  - Package-Name: ``name``, ``package``, ``pkg``, ``dependency``
  - Version: ``version``, ``ver``, ``pinned_version``, ``installed``

Falls kein Header erkannt wird: erste Spalte = Name, zweite = Version.

Sicherheit:
  - Dateipfad wird ueber validate_file_path geprueft (Path-Traversal-Schutz)
  - Nur.xlsx Dateien erlaubt
  - Liest nur das erste Sheet (kein Sheet-Name-Injection)
  - Max 10 000 Zeilen

Schichtzugehoerigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.exceptions import ValidationError
from core.security.validators import validate_file_path
from tools.dependency_auditor.data.requirements_parser import _normalize_name
from tools.dependency_auditor.domain.models import DependencyInfo

_MAX_ROWS = 10_000

_NAME_HEADERS = {"name", "package", "pkg", "dependency", "paket", "module"}
_VERSION_HEADERS = {
    "version",
    "ver",
    "pinned_version",
    "installed",
    "installed_version",
    "version_pinned",
    "release",
}


def parse_xlsx_dependencies(file_path: str) -> list[DependencyInfo]:
    """Parst eine Excel-Datei mit Package-Informationen.

    Liest das erste Sheet. Erkennt Name- und Version-Spalten automatisch
    anhand gaengiger Header-Bezeichnungen.

    Args:
        file_path: Pfad zur.xlsx-Datei (wird validiert).

    Returns:
        Liste der geparsten DependencyInfo-Objekte.

    Raises:
        ValueError: Wenn der Pfad ungueltig, keine Name-Spalte gefunden oder
                    openpyxl nicht installiert ist.
        FileNotFoundError: Wenn die Datei nicht existiert.
        RuntimeError: Wenn openpyxl fehlt.
    """
    try:
        import openpyxl  # noqa: PLC0415
    except ImportError as exc:
        raise ValidationError("openpyxl nicht installiert — pip install openpyxl") from exc

    validated = validate_file_path(file_path, ["xlsx"])
    wb = openpyxl.load_workbook(validated, read_only=True, data_only=True)
    ws = wb.worksheets[0]

    rows = list(ws.iter_rows(values_only=True))
    wb.close()

    if not rows:
        return []

    # Header-Zeile analysieren
    header = [str(c).strip().lower() if c is not None else "" for c in rows[0]]
    name_col = _find_col(header, _NAME_HEADERS)
    version_col = _find_col(header, _VERSION_HEADERS)

    data_rows = rows[1:]
    if name_col is None:
        # Kein Header erkannt: erste Spalte = Name, zweite = Version
        name_col = 0
        version_col = 1 if len(header) > 1 else None
        data_rows = rows  # Header-Zeile als Daten behandeln

    result: list[DependencyInfo] = []
    for line_no, row in enumerate(data_rows[:_MAX_ROWS], start=2):
        if len(row) <= name_col:
            continue
        raw_name = row[name_col]
        if raw_name is None or str(raw_name).strip() == "":
            continue

        name = _normalize_name(str(raw_name).strip())

        raw_version = ""
        if (
            version_col is not None
            and len(row) > version_col
            and row[version_col] is not None
        ):
            raw_version = str(row[version_col]).strip()

        version_pinned = (
            raw_version if raw_version and _looks_like_version(raw_version) else None
        )
        version_spec = f"=={version_pinned}" if version_pinned else raw_version

        result.append(
            DependencyInfo(
                name=name,
                version_pinned=version_pinned,
                version_spec=version_spec,
                line_number=line_no,
            )
        )

    return result


def _find_col(header: list[str], candidates: set[str]) -> int | None:
    """Findet den Index einer Spalte anhand gaengiger Namen.

    Args:
        header: Liste der normalisierten Header-Strings.
        candidates: Menge erlaubter Header-Namen.

    Returns:
        Spalten-Index oder None wenn nicht gefunden.
    """
    for idx, h in enumerate(header):
        if h in candidates:
            return idx
    return None


def _looks_like_version(s: str) -> bool:
    """Prueft ob ein String wie eine Versions-Angabe aussieht.

    Akzeptiert z. B. ``"2.31.0"``, ``"1.0"``, ``"3"``.
    Lehnt Bereichs-Specs wie ``">=2.0"`` ab.

    Args:
        s: Zu pruefender String.

    Returns:
        True wenn es sich um eine einfache Versions-Nummer handelt.
    """
    import re  # noqa: PLC0415

    return bool(re.match(r"^\d+(\.\d+)*([a-zA-Z0-9._-]*)?$", s))
