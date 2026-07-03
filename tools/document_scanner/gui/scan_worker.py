"""
scan_worker — QThread fuer asynchrone Document-Scans.

Iter 1 lief synchron im Main-Thread. Bei groesseren Office- oder
Archive-Dateien (oletools-VBA-Parser, ZIP-Entries-Iteration) kann ein
Scan mehrere hundert Millisekunden dauern — die UI friert ein, der
User merkt's.

Iter 2: Jeder Scan laeuft in einem eigenen
QThread. Das Widget zeigt waehrenddessen einen Spinner/Ladekarte und
ersetzt sie bei ``finished`` durch die fertige ResultCard.

Threading-Vertrag:
- Worker laeuft genau einen Scan, emittiert ``finished`` oder
  ``failed`` und beendet sich.
- Keine direkten Widget-Manipulationen aus dem Worker — alles ueber
  Qt-Signal/Slot ueber Cross-Thread-Connections.
- Bei Exception im Worker wird ``failed(str)`` mit der Fehlernachricht
  emittiert, der Thread terminiert sauber.

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from core.logger import get_logger
from tools.document_scanner.application.scanner_service import DocumentScannerService

_log = get_logger(__name__)


class ScanWorker(QThread):
    """Fuehrt einen einzelnen Document-Scan in einem QThread aus.

    Signals:
        finished(DocumentScanResult): Scan erfolgreich abgeschlossen.
        failed(str): Scan ist gescheitert (Fehlertext).
    """

    finished = Signal(object)  # DocumentScanResult
    failed = Signal(str)

    def __init__(
        self,
        service: DocumentScannerService,
        source: Path,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._source = source

    def run(self) -> None:
        """Laeuft im neuen Thread — emittiert ``finished`` oder ``failed``."""
        try:
            result = self._service.scan(self._source)
        except FileNotFoundError as exc:
            self.failed.emit(f"Datei nicht gefunden: {exc}")
            return
        except OSError as exc:
            self.failed.emit(
                f"Schreibzugriff auf Quarantaene fehlgeschlagen ({exc})."
            )
            return
        except Exception as exc:  # noqa: BLE001 -- Pipeline darf nie crashen
            _log.exception("ScanWorker: unerwartete Exception")
            self.failed.emit(f"Unerwarteter Fehler: {type(exc).__name__}")
            return
        self.finished.emit(result)
