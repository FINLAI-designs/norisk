"""
validation_report — Datenklassen und Enums für den Secure Import Validator.

Dieses Modul definiert die strukturierten Rückgabetypen von
``core.security.import_validator.validate_import``. Es wird ebenfalls vom
PDF-Risk-Scanner und Email-Attachment-Scanner konsumiert und ist daher
bewusst klein, reiner Pure-Python-Code ohne GUI- oder Core-Security-Imports.

Begriffe
--------
- **Severity:** Schweregrad einer einzelnen Threat (INFO..CRITICAL).
- **ImportType:** Erwarteter Datei-Typ, den der Aufrufer deklariert.
- **Threat:** Eine einzelne erkannte Bedrohung mit stabilem Code + Kontext.
- **ValidationReport:** Aggregat aller Threats + Risk-Score (0–100).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Severity — stabile Punktwerte für Risk-Score-Aggregation
# ---------------------------------------------------------------------------

# Punktwerte je Severity. Werden in ValidationReport.risk_score aggregiert.
_SEVERITY_POINTS: dict[str, int] = {
    "INFO": 0,
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 50,
    "CRITICAL": 100,
}


class Severity(Enum):
    """Schweregrad einer einzelnen erkannten Threat."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def points(self) -> int:
        """Punktwert für Risk-Score-Aggregation."""
        return _SEVERITY_POINTS[self.value]


# ---------------------------------------------------------------------------
# ImportType — vom Aufrufer deklarierter Datei-Typ
# ---------------------------------------------------------------------------


class ImportType(Enum):
    """Datei-Typ, den der Aufrufer beim ``validate_import``-Aufruf deklariert.

    ``UNKNOWN`` ist ein expliziter Fallback — dann läuft nur der
    ``generic_validator`` (Magika + Größen-Guard).

    Erweiterung: DOCX/PPTX/ODT/RTF/ZIP/SEVENZIP/JS/
    VBS/PS1/BAT/SVG fuer den Document-Scanner Iter 2.
    """

    XLSX = "xlsx"
    XLSM = "xlsm"
    DOCX = "docx"
    DOCM = "docm"
    PPTX = "pptx"
    PPTM = "pptm"
    ODT = "odt"
    RTF = "rtf"
    JSON = "json"
    JSONL = "jsonl"
    TXT = "txt"
    CSV = "csv"
    PDF = "pdf"
    EML = "eml"
    MSG = "msg"
    ZIP = "zip"
    SEVENZIP = "7z"
    RAR = "rar"
    JS = "js"
    VBS = "vbs"
    PS1 = "ps1"
    BAT = "bat"
    LNK = "lnk"
    SVG = "svg"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Threat — einzelner Indicator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Threat:
    """Eine einzelne erkannte Bedrohung.

    Attributes:
        code: Stabiler Schlüssel, z. B. ``"XLSX_FORMULA_INJECTION"``.
            Dokumentiert in ``docs/SECURITY_THREATS.md``.
        severity: Schweregrad.
        message: Für den Benutzer lesbare Beschreibung (deutsch).
        context: Zusatzdaten wie Zellreferenz, Byte-Offset, URL.
            Werden in Reports ausgegeben, aber nicht geloggt
            (können sensible Ausschnitte enthalten).
    """

    code: str
    severity: Severity
    message: str
    context: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# ValidationReport — Aggregat
# ---------------------------------------------------------------------------

# Obergrenze für risk_score — mehrere HIGH-Threats sollen 100 erreichen
# können, ohne zu überlaufen.
_RISK_SCORE_MAX = 100

# Threat-Code-Endungen, die eine UNVOLLSTAENDIGE Inspektion markieren: ein
# Validator/Parser konnte die Datei nicht (vollstaendig) pruefen. Fail-Closed
#: ein solcher Report darf NIE als „sicher" gelten — aktive Inhalte
# koennen unentdeckt geblieben sein (z.B. PDF mit kaputtem xref, das pypdf
# ablehnt, in Adobe/Foxit aber oeffnet und seine OpenAction-JS ausfuehrt).
# Konvention statt fester Liste, damit kuenftige ``*_SCAN_ERROR``-Codes
# automatisch fail-closed sind und der Fail-Open nicht erneut entstehen kann.
_SCAN_INCOMPLETE_SUFFIXES: tuple[str, ...] = (
    "_SCAN_ERROR",
    "_PARSE_ERROR",
    "_READ_ERROR",
    "_SCAN_UNAVAILABLE",
    "_SCAN_SKIPPED",
    "_VALIDATOR_ERROR",
)

# Einzel-Codes ohne eindeutige Endung, die ebenfalls eine eingeschraenkte
# Inspektion bedeuten (statische Analyse unvollstaendig).
_SCAN_INCOMPLETE_CODES: frozenset[str] = frozenset({"PDF_ENCRYPTED"})


@dataclass
class ValidationReport:
    """Aggregat aller Threats + Metadaten einer Validierung.

    Attributes:
        path: Validierter (ggf. resolved) Pfad.
        declared_type: Was der Aufrufer als ``expected`` übergeben hat.
        detected_mime: MIME-Type aus Magika (z. B. ``"application/pdf"``).
        detected_label: Magika-Label (z. B. ``"pdf"``, ``"exe"``, ``"zip"``).
        type_match: True wenn Magika-Ergebnis zur deklarierten
            ``ImportType`` kompatibel ist.
        threats: Liste aller erkannten Threats (Append-Order).
        risk_score: Summe der Severity-Punkte, capped auf 100.
        safe_to_parse: False wenn mindestens eine CRITICAL-Threat vorliegt.
        duration_ms: Messdauer der Validierung (Wall-Clock, Millisekunden).
    """

    path: Path
    declared_type: ImportType
    detected_mime: str = ""
    detected_label: str = ""
    type_match: bool = True
    threats: list[Threat] = field(default_factory=list)
    risk_score: int = 0
    safe_to_parse: bool = True
    duration_ms: float = 0.0

    def add(self, threat: Threat) -> None:
        """Fügt eine Threat hinzu und aktualisiert Score + safe_to_parse.

        Args:
            threat: Zu registrierende Bedrohung.
        """
        self.threats.append(threat)
        self.risk_score = min(_RISK_SCORE_MAX, self.risk_score + threat.severity.points)
        if threat.severity is Severity.CRITICAL:
            self.safe_to_parse = False

    def has_severity(self, minimum: Severity) -> bool:
        """Prüft ob mindestens eine Threat mit gegebener Mindest-Severity existiert.

        Args:
            minimum: Mindest-Schweregrad.

        Returns:
            True wenn eine Threat diese Schwelle erreicht oder überschreitet.
        """
        threshold = minimum.points
        return any(t.severity.points >= threshold for t in self.threats)

    def scan_incomplete(self) -> bool:
        """Prüft, ob ein Validator die Datei nicht (vollständig) inspizieren konnte.

        Fail-Closed: Ein Report mit einer solchen Markierung darf NIE als
        „sicher" eingestuft werden, da aktive Inhalte unentdeckt geblieben sein
        können (Parse-Abbruch, fehlender Deep-Scanner, Verschlüsselung …).

        Returns:
            True, wenn mindestens eine Threat eine unvollständige Inspektion
            markiert (Code endet auf eine bekannte Fehler-/Unavailable-Endung
            oder steht in:data:`_SCAN_INCOMPLETE_CODES`).
        """
        return any(
            t.code in _SCAN_INCOMPLETE_CODES
            or t.code.endswith(_SCAN_INCOMPLETE_SUFFIXES)
            for t in self.threats
        )
