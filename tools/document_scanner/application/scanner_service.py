"""
scanner_service — Orchestriert den Document-Scan-Workflow.

Pipeline:

1. ``QuarantineManager.quarantine(source)`` — Datei kopieren, read-only
   setzen, SHA-256 berechnen.
2. Magika-Typ ueber die Datei-Endung mappen →:class:`ImportType`.
3. ``validate_import(deep_scan=True)`` — Layer 0+1+2-Check.
4. ``ScanVerdict`` aus dem ``ValidationReport.risk_score`` ableiten.

Backed durch die bestehende ``core.security``-Pipeline — kein neuer
Validator-Code. Iter 2 erweitert um Office-Sub-Validator.

Schichtzugehoerigkeit: application/ — darf domain/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import time
from pathlib import Path

from core.logger import get_logger
from core.security.import_validator import validate_import
from core.security.validation_report import ImportType, Severity
from tools.document_scanner.application.quarantine_manager import QuarantineManager
from tools.document_scanner.domain.models import (
    DocumentScanResult,
    ScanVerdict,
)

# Repository wird lazy importiert damit Tests ohne EncryptedDatabase laufen.

_log = get_logger(__name__)


#: Mapping Datei-Endung →:class:`ImportType`. Fehlt eine Endung,
#: fallen wir auf ``ImportType.UNKNOWN`` zurueck (generic_validator).
#:
#:: Office/Archive/Script/SVG ergaenzt.
_EXTENSION_MAP: dict[str, ImportType] = {
    ".pdf": ImportType.PDF,
    ".xlsx": ImportType.XLSX,
    ".xlsm": ImportType.XLSM,
    ".docx": ImportType.DOCX,
    ".docm": ImportType.DOCM,
    ".pptx": ImportType.PPTX,
    ".pptm": ImportType.PPTM,
    ".odt": ImportType.ODT,
    ".rtf": ImportType.RTF,
    ".json": ImportType.JSON,
    ".jsonl": ImportType.JSONL,
    ".txt": ImportType.TXT,
    ".csv": ImportType.CSV,
    ".eml": ImportType.EML,
    ".msg": ImportType.MSG,
    ".zip": ImportType.ZIP,
    ".7z": ImportType.SEVENZIP,
    ".rar": ImportType.RAR,
    ".js": ImportType.JS,
    ".vbs": ImportType.VBS,
    ".ps1": ImportType.PS1,
    ".bat": ImportType.BAT,
    ".cmd": ImportType.BAT,
    ".lnk": ImportType.LNK,
    ".svg": ImportType.SVG,
}


def _classify(report) -> ScanVerdict:
    """Leitet den:class:`ScanVerdict` aus einem ``ValidationReport`` ab.

    Logik:
        - ``safe_to_parse == False`` → DANGEROUS
        - mindestens ein CRITICAL-Threat → DANGEROUS
        - mindestens ein HIGH oder MEDIUM-Threat → SUSPICIOUS
        - unvollständige Inspektion (auch LOW/INFO-Marker) → SUSPICIOUS
        - sonst → SAFE
    """
    if not report.safe_to_parse:
        return ScanVerdict.DANGEROUS
    if report.has_severity(Severity.CRITICAL):
        return ScanVerdict.DANGEROUS
    if report.has_severity(Severity.HIGH) or report.has_severity(Severity.MEDIUM):
        return ScanVerdict.SUSPICIOUS
    # Fail-Closed: konnte die Datei nicht vollständig geprüft werden
    # (z.B. übersprungener Formula-Scan, fehlender Deep-Scanner — oft nur
    # LOW/INFO), nie „sicher" melden.
    if report.scan_incomplete():
        return ScanVerdict.SUSPICIOUS
    return ScanVerdict.SAFE


def _import_type_for(path: Path) -> ImportType:
    """Ermittelt den deklarierten:class:`ImportType` aus der Datei-Endung."""
    return _EXTENSION_MAP.get(path.suffix.lower(), ImportType.UNKNOWN)


class DocumentScannerService:
    """Hauptservice fuer Drag&Drop-basiertes Datei-Scanning.

    Eine Instanz pro Tool-Widget reicht. Der Service haelt einen
:class:`QuarantineManager` als Member; Cleanup beim App-Beenden
    erfolgt ueber:meth:`shutdown`.
    """

    def __init__(
        self,
        quarantine: QuarantineManager | None = None,
        history=None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            quarantine: Optional vor-erstellter Quarantaene-Manager
                (Tests). Default: neue Instanz mit Standard-Root.
            history: Optional vor-erstelltes:class:`HistoryRepository`.
                Bei ``None`` wird lazy beim ersten Scan-Eintrag eines
                erstellt — Failure (z. B. keine EncryptedDatabase
                konfiguriert) schluckt der Service und loggt nur.
        """
        self._quarantine = quarantine or QuarantineManager()
        self._history = history
        self._history_init_failed = False

    @property
    def quarantine(self) -> QuarantineManager:
        """Gibt den verwendeten Quarantaene-Manager zurueck."""
        return self._quarantine

    @property
    def history(self):  # type: ignore[no-untyped-def]
        """Lazy-initialisiert das HistoryRepository und gibt es zurueck.

        Wird vom Widget gebraucht um den History-Tab zu fuellen. Bei
        Init-Fehler (EncryptedDatabase nicht konfiguriert) wird ``None``
        zurueckgegeben — die UI behandelt das als "History leer".
        """
        if self._history is not None or self._history_init_failed:
            return self._history
        try:
            from tools.document_scanner.data.history_repository import (  # noqa: PLC0415
                HistoryRepository,
            )

            self._history = HistoryRepository()
        except Exception as exc:  # noqa: BLE001 -- gleicher Vertrag wie _persist_history
            _log.warning("Document-Scan-History deaktiviert: %s", exc)
            self._history_init_failed = True
        return self._history

    def scan(self, source: Path) -> DocumentScanResult:
        """Fuehrt den vollstaendigen Scan auf einer Datei aus.

        Args:
            source: Pfad zur Datei wie sie der User abgelegt hat. Wird
                in die Quarantaene kopiert — die Original-Datei bleibt
                unangetastet.

        Returns:
:class:`DocumentScanResult` mit Quarantaene-Entry, Verdict,
            Risk-Score, Magika-Label und allen Threats.

        Raises:
            FileNotFoundError: Wenn ``source`` nicht existiert.
        """
        t0 = time.perf_counter()
        entry = self._quarantine.quarantine(Path(source))

        expected = _import_type_for(entry.stored_path)
        deep = expected == ImportType.PDF
        report = validate_import(
            entry.stored_path, expected=expected, deep_scan=deep
        )

        verdict = _classify(report)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        result = DocumentScanResult(
            entry=entry,
            verdict=verdict,
            risk_score=report.risk_score,
            magika_label=report.detected_label,
            type_match=report.type_match,
            threats=list(report.threats),
            validation_report=report,
            duration_ms=duration_ms,
        )
        _log.info(
            "Document-Scan abgeschlossen: file=%s magika=%s verdict=%s score=%d threats=%d dur_ms=%.1f",
            entry.original_name,
            report.detected_label,
            verdict.value,
            report.risk_score,
            len(report.threats),
            duration_ms,
        )
        self._persist_history(result)
        return result

    def _persist_history(self, result: DocumentScanResult) -> None:
        """Schreibt den Scan in die History — Failure ist nicht-fatal."""
        if self._history_init_failed:
            return
        if self._history is None:
            try:
                from tools.document_scanner.data.history_repository import (  # noqa: PLC0415
                    HistoryRepository,
                )

                self._history = HistoryRepository()
            except Exception as exc:  # noqa: BLE001 -- History-DB-Init darf den Scan nie blockieren
                _log.warning(
                    "Document-Scan-History deaktiviert (DB-Init fehlgeschlagen): %s",
                    exc,
                )
                self._history_init_failed = True
                return
        try:
            self._history.add(result)
        except Exception as exc:  # noqa: BLE001 -- gleicher Vertrag wie oben
            _log.warning("Document-Scan-History-Write fehlgeschlagen: %s", exc)

    def delete(self, result: DocumentScanResult) -> None:
        """Entfernt einen Scan-Eintrag inkl. Quarantaene-Datei.

        Wird vom UI-Button "Loeschen" aufgerufen.
        """
        self._quarantine.remove(result.entry)

    def shutdown(self) -> int:
        """Beendet den Service: alle Quarantaene-Slots werden geloescht.

        Sollte beim App-Beenden aufgerufen werden (``aboutToQuit``).

        Returns:
            Anzahl entfernter Slots.
        """
        return self._quarantine.cleanup_all()
