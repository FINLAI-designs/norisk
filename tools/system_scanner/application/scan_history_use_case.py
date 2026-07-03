"""
scan_history_use_case — Use Case: Scan-Verlauf abrufen.

Gibt vergangene Scan-Ergebnisse aus dem Repository zurück.

Schichtzugehörigkeit: application/ — keine GUI-Imports, keine direkten DB-Calls.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from tools.system_scanner.domain.entities import ScanResult
from tools.system_scanner.domain.interfaces import IScanRepository

log = get_logger(__name__)

# Standardlimit für Verlaufsabfragen
_DEFAULT_HISTORY_LIMIT = 10


def create_default_scan_history_use_case() -> ScanHistoryUseCase:
    """Default-Factory mit ``ScanRepository`` RUN2-GUI).

    Erlaubt Cross-Tool-GUIs (security_scoring) den Use Case zu beziehen
    ohne ``data/`` direkt zu importieren.

    Returns:
        ``ScanHistoryUseCase`` mit production-tauglichem Repository.
    """
    from tools.system_scanner.data.scanner_repository import (  # noqa: PLC0415
        ScanRepository,
    )

    return ScanHistoryUseCase(ScanRepository())


class ScanHistoryUseCase:
    """Gibt den Scan-Verlauf aus dem Repository zurück.

    Attributes:
        _repository: Persistenz-Adapter (IScanRepository).
    """

    def __init__(self, repository: IScanRepository) -> None:
        """Initialisiert den Use Case.

        Args:
            repository: IScanRepository-Implementierung.
        """
        self._repository = repository

    def get_latest(self) -> ScanResult | None:
        """Gibt das aktuellste Scan-Ergebnis zurück.

        Returns:
            Letztes ScanResult oder None wenn noch kein Scan durchgeführt wurde.
        """
        result = self._repository.load_latest()
        if result:
            log.debug("Letzter Scan geladen: %s", result.scan_id[:8])
        else:
            log.debug("Kein Scan-Ergebnis in der Datenbank")
        return result

    def get_history(self, limit: int = _DEFAULT_HISTORY_LIMIT) -> list[ScanResult]:
        """Gibt die letzten N Scan-Ergebnisse zurück.

        Args:
            limit: Maximale Anzahl (Standard: 10).

        Returns:
            Scan-Ergebnisse, neueste zuerst.
        """
        results = self._repository.load_history(limit=limit)
        log.debug("Scan-Verlauf geladen: %d Einträge", len(results))
        return results
