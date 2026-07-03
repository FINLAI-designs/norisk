"""
sub_validators — Format-spezifische Validierer für den Secure Import Validator.

Jeder Sub-Validator prüft format-spezifische Angriffs-Indikatoren, die ein
reiner Typ-Check nicht erkennt (Makros in XLSX, Trojan-Source in TXT,
JSON-Depth-DoS usw.). Sie werden nicht direkt aufgerufen, sondern über die
``get_sub_validator``-Registry vom Haupt-Validator orchestriert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.security.sub_validators.base import SubValidator
from core.security.validation_report import ImportType


def get_sub_validator(import_type: ImportType) -> SubValidator:
    """Gibt den passenden Sub-Validator für einen ImportType zurück.

    Unbekannte / nicht speziell abgedeckte Typen fallen auf den
    ``GenericValidator`` zurück (Magika + Größen-Guard).

    Args:
        import_type: Deklarierter ImportType.

    Returns:
        Eine SubValidator-Instanz, die ``validate`` implementiert.
    """
    # Lazy imports vermeiden Loading-Kosten für ungenutzte Validatoren
    # (z. B. oletools + openpyxl werden nicht geladen, wenn nur TXT validiert
    # wird).
    if import_type in (ImportType.XLSX, ImportType.XLSM):
        from core.security.sub_validators.xlsx_validator import XlsxValidator

        return XlsxValidator()
    if import_type in (
        ImportType.DOCX,
        ImportType.DOCM,
        ImportType.PPTX,
        ImportType.PPTM,
        ImportType.ODT,
    ):
        from core.security.sub_validators.office_validator import OfficeValidator

        return OfficeValidator()
    if import_type in (
        ImportType.ZIP,
        ImportType.SEVENZIP,
        ImportType.RAR,
    ):
        from core.security.sub_validators.archive_validator import ArchiveValidator

        return ArchiveValidator()
    if import_type in (
        ImportType.JS,
        ImportType.VBS,
        ImportType.PS1,
        ImportType.BAT,
        ImportType.LNK,
    ):
        from core.security.sub_validators.script_validator import ScriptValidator

        return ScriptValidator()
    if import_type is ImportType.SVG:
        from core.security.sub_validators.svg_validator import SvgValidator

        return SvgValidator()
    if import_type in (ImportType.JSON, ImportType.JSONL):
        from core.security.sub_validators.json_validator import JsonValidator

        return JsonValidator()
    if import_type in (ImportType.TXT, ImportType.CSV):
        from core.security.sub_validators.txt_validator import TxtValidator

        return TxtValidator()
    if import_type is ImportType.PDF:
        from core.security.sub_validators.pdf_validator import PdfValidator

        return PdfValidator()

    from core.security.sub_validators.generic_validator import GenericValidator

    return GenericValidator()


__all__ = ["SubValidator", "get_sub_validator"]
