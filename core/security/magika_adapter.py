"""
magika_adapter — Wrapper um den Magika-Typerkenner.

Magika (https://github.com/google/magika) ist ein AI-basierter
Dateityp-Erkenner von Google (Apache 2.0). Er erkennt die tatsächliche
inhaltsbasierte Datei-Art — unabhängig von der Dateiendung. Damit werden
Spoofing-Angriffe erkannt (``.exe`` als ``.pdf`` getarnt usw.).

Dieses Modul kapselt:
  - Die einmalige Initialisierung der ``Magika``-Instanz (teuer: lädt ein
    ONNX-Modell in den Speicher).
  - Die Abbildung der Magika-Labels auf FINLAI's ``ImportType``.
  - Die Robustheit gegenüber fehlenden/korrupten Dateien.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from core.logger import get_logger
from core.security.validation_report import ImportType

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Label-Mapping: Magika-Label → passender ImportType
#
# Quelle der Labels: https://github.com/google/magika/blob/main/docs/labels.md
# ---------------------------------------------------------------------------

# Magika-Labels die kompatibel zu XLSX/XLSM sind
_XLSX_LABELS: frozenset[str] = frozenset(
    {"xlsx", "xlsb", "xlsm", "zip", "docx", "ooxml"}
)

# Magika-Labels die kompatibel zu JSON/JSONL sind
_JSON_LABELS: frozenset[str] = frozenset({"json", "jsonl", "txt"})

# Magika-Labels die kompatibel zu TXT/CSV sind
_TEXT_LABELS: frozenset[str] = frozenset(
    {"txt", "csv", "tsv", "ini", "yaml", "toml", "md", "rtf"}
)

# Magika-Labels die kompatibel zu PDF sind
_PDF_LABELS: frozenset[str] = frozenset({"pdf"})

# Magika-Labels die kompatibel zu EML sind
_EML_LABELS: frozenset[str] = frozenset({"eml", "mbox", "mht"})

# Magika-Labels die kompatibel zu MSG sind (CFBF/OLE-Container)
_MSG_LABELS: frozenset[str] = frozenset({"msg", "cfbf", "ole"})

# Office/Archive/Script-Erweiterungen fuer den
# Document-Scanner Iter 2.
_DOCX_LABELS: frozenset[str] = frozenset({"docx", "doc", "ooxml", "zip", "odt"})
_PPTX_LABELS: frozenset[str] = frozenset({"pptx", "ppt", "ooxml", "zip"})
_ZIP_LABELS: frozenset[str] = frozenset({"zip", "7z", "rar", "ooxml", "iso"})
_JS_LABELS: frozenset[str] = frozenset({"javascript", "txt"})
_VBS_LABELS: frozenset[str] = frozenset({"vba", "txt"})
_PS1_LABELS: frozenset[str] = frozenset({"powershell", "txt"})
_BAT_LABELS: frozenset[str] = frozenset({"bat", "txt"})
_LNK_LABELS: frozenset[str] = frozenset({"lnk", "winshortcut"})
_SVG_LABELS: frozenset[str] = frozenset({"svg", "xml", "txt"})

# Mapping: ImportType → Menge akzeptierter Magika-Labels
_ACCEPTED: dict[ImportType, frozenset[str]] = {
    ImportType.XLSX: _XLSX_LABELS,
    ImportType.XLSM: _XLSX_LABELS,
    ImportType.DOCX: _DOCX_LABELS,
    ImportType.DOCM: _DOCX_LABELS,
    ImportType.PPTX: _PPTX_LABELS,
    ImportType.PPTM: _PPTX_LABELS,
    ImportType.ODT: _DOCX_LABELS,
    ImportType.RTF: _TEXT_LABELS,
    ImportType.JSON: _JSON_LABELS,
    ImportType.JSONL: _JSON_LABELS,
    ImportType.TXT: _TEXT_LABELS,
    ImportType.CSV: _TEXT_LABELS,
    ImportType.PDF: _PDF_LABELS,
    ImportType.EML: _EML_LABELS,
    ImportType.MSG: _MSG_LABELS,
    ImportType.ZIP: _ZIP_LABELS,
    ImportType.SEVENZIP: _ZIP_LABELS,
    ImportType.RAR: _ZIP_LABELS,
    ImportType.JS: _JS_LABELS,
    ImportType.VBS: _VBS_LABELS,
    ImportType.PS1: _PS1_LABELS,
    ImportType.BAT: _BAT_LABELS,
    ImportType.LNK: _LNK_LABELS,
    ImportType.SVG: _SVG_LABELS,
}

# Magika-Labels die auf ausführbare/gefährliche Payloads hindeuten.
# Werden als CRITICAL gemeldet wenn sie statt des erwarteten Typs erkannt
# werden (typisches Täuschungs-Muster).
DANGEROUS_LABELS: frozenset[str] = frozenset(
    {
        "pebin",  # Windows PE (exe/dll)
        "elfbin",  # Linux ELF
        "macho",  # macOS Mach-O
        "msdownload",
        "jar",
        "javabytecode",
        "dex",  # Android Dalvik
        "coff",
        "wasm",
        "bat",
        "powershell",
        "javascript",
        "vba",
        "html",  # HTML in TXT-/JSON-Kontext = verdächtig
    }
)


@dataclass(frozen=True)
class MagikaIdentification:
    """Ergebnis einer Magika-Erkennung, reduziert auf die nötigen Felder."""

    label: str
    mime_type: str
    description: str
    score: float
    is_text: bool

    @property
    def is_dangerous(self) -> bool:
        """True wenn das Label auf ausführbaren/aktiven Code hindeutet."""
        return self.label in DANGEROUS_LABELS


# ---------------------------------------------------------------------------
# Singleton-Initialisierung
# ---------------------------------------------------------------------------

_magika_instance = None
_magika_lock = Lock()


def _get_magika():  # type: ignore[no-untyped-def]
    """Initialisiert die Magika-Instanz einmalig (thread-safe).

    Returns:
        Die globale ``magika.Magika``-Instanz.
    """
    global _magika_instance
    if _magika_instance is None:
        with _magika_lock:
            if _magika_instance is None:
                from magika import Magika  # noqa: PLC0415

                _magika_instance = Magika()
                _log.debug("Magika-Instanz initialisiert.")
    return _magika_instance


# ---------------------------------------------------------------------------
# Öffentliche Funktionen
# ---------------------------------------------------------------------------


def identify(path: Path) -> MagikaIdentification:
    """Erkennt den Content-Typ einer Datei mittels Magika.

    Bei Lesefehlern (Datei existiert nicht, Berechtigungsfehler) wird
    ein ``MagikaIdentification`` mit ``label="unknown"`` und Score 0.0
    zurückgegeben — es wird keine Exception geworfen, damit der
    Haupt-Validator eine strukturierte Threat produzieren kann.

    Args:
        path: Zu analysierende Datei.

    Returns:
        ``MagikaIdentification`` mit Label, MIME-Type, Beschreibung, Score.
    """
    try:
        magika = _get_magika()
        result = magika.identify_path(path)
        out = result.output
        return MagikaIdentification(
            label=out.label,
            mime_type=out.mime_type,
            description=out.description,
            score=float(result.score),
            is_text=bool(out.is_text),
        )
    except FileNotFoundError:
        _log.warning("Magika: Datei nicht gefunden: %s", path.name)
        return MagikaIdentification(
            label="unknown",
            mime_type="application/octet-stream",
            description="Datei nicht gefunden",
            score=0.0,
            is_text=False,
        )
    except PermissionError:
        _log.warning("Magika: Kein Lesezugriff: %s", path.name)
        return MagikaIdentification(
            label="unknown",
            mime_type="application/octet-stream",
            description="Kein Lesezugriff",
            score=0.0,
            is_text=False,
        )
    except Exception as exc:  # noqa: BLE001 -- Magika (third-party ML-Model) kann interne Errors werfen, Scanner darf nie crashen
        _log.error("Magika-Erkennung fehlgeschlagen für %s: %s", path.name, exc)
        return MagikaIdentification(
            label="unknown",
            mime_type="application/octet-stream",
            description="Magika-Fehler",
            score=0.0,
            is_text=False,
        )


def is_compatible(detected_label: str, expected: ImportType) -> bool:
    """Prüft ob ein Magika-Label mit dem erwarteten ImportType kompatibel ist.

    ``ImportType.UNKNOWN`` akzeptiert jedes Label (kein Type-Check).

    Args:
        detected_label: Magika-Label aus ``identify``.
        expected: Vom Aufrufer deklarierter ImportType.

    Returns:
        True wenn das Label im Akzeptanz-Set für den ImportType liegt.
    """
    if expected is ImportType.UNKNOWN:
        return True
    accepted = _ACCEPTED.get(expected, frozenset())
    return detected_label in accepted
