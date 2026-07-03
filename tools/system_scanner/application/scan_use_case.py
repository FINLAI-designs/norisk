"""
scan_use_case — Use Case: System-Scan durchführen und speichern.

Orchestriert den Scan-Ablauf:
  1. Scan via ISystemScanner durchführen
  2. Ergebnis via IScanRepository persistieren
  3. ScanResult zurückgeben

Schichtzugehörigkeit: application/ — keine GUI-Imports, keine direkten DB-Calls.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from tools.system_scanner.domain.entities import ScanResult
from tools.system_scanner.domain.interfaces import IScanRepository, ISystemScanner

log = get_logger(__name__)


class ScanUseCase:
    """Führt einen System-Scan durch und speichert das Ergebnis.

    Attributes:
        _scanner: Plattform-spezifischer Scanner (ISystemScanner).
        _repository: Persistenz-Adapter (IScanRepository).
    """

    def __init__(
        self,
        scanner: ISystemScanner,
        repository: IScanRepository,
    ) -> None:
        """Initialisiert den Use Case mit Abhängigkeiten.

        Args:
            scanner: ISystemScanner-Implementierung.
            repository: IScanRepository-Implementierung.
        """
        self._scanner = scanner
        self._repository = repository

    def execute(self) -> ScanResult:
        """Führt den Scan durch, speichert das Ergebnis und gibt es zurück.

        Returns:
            Vollständiges ScanResult.

        Raises:
            RuntimeError: Wenn der Scan fehlschlägt.
        """
        log.info("System-Scan Use Case gestartet")
        result = self._scanner.scan()
        log.info(
            "Scan abgeschlossen: %d Komponenten, %d Warnungen",
            len(result.security_components),
            len(result.warnings),
        )
        try:
            self._repository.save(result)
            log.debug("Scan-Ergebnis gespeichert: %s", result.scan_id[:8])
        except Exception as exc:  # noqa: BLE001
            log.warning("Scan-Ergebnis konnte nicht gespeichert werden: %s", exc)
        return result
