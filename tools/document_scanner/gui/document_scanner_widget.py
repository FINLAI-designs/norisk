"""
document_scanner_widget — Hauptansicht des Document Scanners.

Komposition:

- Header mit Erklaerungstext ("Was passiert beim Drag&Drop?")
-:class:`DropzoneWidget` als Eingang
- Scroll-Bereich mit:class:`PendingCard` waehrend Scan +:class:`ResultCard`
  nach Abschluss

Pipeline:
1. ``DropzoneWidget.file_dropped`` → ``_on_file_dropped``
2. Sofort eine:class:`PendingCard` einsetzen (UI bleibt responsiv)
3.:class:`ScanWorker` als QThread starten → ``finished``/``failed``
4. PendingCard durch ResultCard ersetzen (oder Fehler-Hinweis)
5. "Loeschen"-Klick → Quarantaene wegraeumen + Card entfernen

Schichtzugehoerigkeit: gui/ — darf application/, core/ importieren.

Author: Patrick Riederich
Version: 0.2
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QLabel,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from tools.document_scanner.application.scanner_service import DocumentScannerService
from tools.document_scanner.domain.models import DocumentScanResult
from tools.document_scanner.gui.dropzone_widget import DropzoneWidget
from tools.document_scanner.gui.history_view import HistoryView
from tools.document_scanner.gui.pending_card import PendingCard
from tools.document_scanner.gui.result_card import ResultCard
from tools.document_scanner.gui.scan_worker import ScanWorker

_log = get_logger(__name__)

_INFO_TEXT = (
    "Ziehe eine Datei oder einen E-Mail-Anhang in die Drop-Zone. "
    "NoRisk kopiert die Datei in einen Schutzbereich, prueft den "
    "tatsaechlichen Dateityp (Magika), fuehrt eine statische Analyse "
    "aus und zeigt das Ergebnis als Karte. Die Datei wird NIE "
    "automatisch geoeffnet — beim Beenden von NoRisk wird der "
    "Schutzbereich vollstaendig geloescht."
)


class DocumentScannerWidget(QWidget):
    """Hauptansicht des Document Scanners."""

    def __init__(
        self,
        service: DocumentScannerService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or DocumentScannerService()
        self._cards: list[ResultCard] = []
        self._workers: list[ScanWorker] = []
        self._build_ui()
        theme.register_listener(self._apply_style)
        self._apply_style()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        title = QLabel("Dokument-Scanner")
        title.setObjectName("DocumentScannerTitle")
        layout.addWidget(title)

        info = QLabel(_INFO_TEXT)
        info.setObjectName("DocumentScannerInfo")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Zwei Tabs — aktuelle Session + History.
        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_session_tab(), "Aktuelle Session")
        # Repository kommt aus dem Service — Hex-Architektur: GUI darf
        # nicht direkt auf data/ greifen.
        self._history_view = HistoryView(repository=self._service.history)
        self._tabs.addTab(self._history_view, "Bisherige Scans")
        layout.addWidget(self._tabs, stretch=1)

    def _build_session_tab(self) -> QWidget:
        """Liefert den Tab mit Dropzone + Live-Cards."""
        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(0, 0, 0, 0)
        host_layout.setSpacing(16)

        self._dropzone = DropzoneWidget()
        self._dropzone.file_dropped.connect(self._on_file_dropped)
        host_layout.addWidget(self._dropzone)

        # Scroll-Bereich fuer die Result-Cards
        self._cards_host = QWidget()
        cards_layout = QVBoxLayout(self._cards_host)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(8)
        cards_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._cards_layout = cards_layout

        self._empty_hint = QLabel(
            "Scannt Dateien auf YARA-Muster, Office-Makros, Archiv-Risiken, "
            "verdächtige Skripte und Typ-Spoofing (Office, PDF, Archive, "
            "Skripte).\n\n"
            "Noch keine gescannten Dateien — lege eine in die "
            "Drop-Zone oben."
        )
        self._empty_hint.setObjectName("DocumentScannerEmptyHint")
        self._empty_hint.setWordWrap(True)
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cards_layout.addWidget(self._empty_hint)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._cards_host)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        host_layout.addWidget(scroll, stretch=1)
        return host

    # ------------------------------------------------------------------
    # Slots — Async-Pipeline
    # ------------------------------------------------------------------

    def _on_file_dropped(self, path: Path) -> None:
        """Slot fuer ``DropzoneWidget.file_dropped`` — startet ScanWorker."""
        if not path.exists():
            _log.warning("Drop ignoriert — Datei weg: %s", path)
            FinlaiInfoDialog(
                title="Datei nicht gefunden",
                message=f"Die Datei {path.name!r} konnte nicht gelesen werden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        pending = self._add_pending_card(path)
        worker = ScanWorker(self._service, path, parent=self)
        worker.finished.connect(lambda r, p=pending: self._on_scan_finished(p, r))
        worker.failed.connect(lambda msg, p=pending: self._on_scan_failed(p, msg))
        worker.finished.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        self._workers.append(worker)
        worker.start()

    def _on_scan_finished(
        self, pending: PendingCard, result: DocumentScanResult
    ) -> None:
        """Ersetzt eine PendingCard durch eine fertige ResultCard."""
        self._replace_pending(pending, ResultCard(result, self._cards_host))

    def _on_scan_failed(self, pending: PendingCard, message: str) -> None:
        """Entfernt die PendingCard und zeigt einen Fehler-Dialog."""
        self._remove_pending(pending)
        FinlaiInfoDialog(
            title="Scan-Fehler",
            message=message,
            icon_name=Icons.ERROR,
            parent=self,
        ).exec()

    # ------------------------------------------------------------------
    # Card-Lifecycle
    # ------------------------------------------------------------------

    def _add_pending_card(self, source: Path) -> PendingCard:
        if self._empty_hint.isVisible():
            self._empty_hint.hide()
        pending = PendingCard(source, parent=self._cards_host)
        self._cards_layout.insertWidget(0, pending)
        return pending

    def _replace_pending(self, pending: PendingCard, card: ResultCard) -> None:
        idx = self._cards_layout.indexOf(pending)
        if idx < 0:
            # Pending bereits weg — Card direkt oben einfuegen
            idx = 0
        pending.stop()
        self._cards_layout.removeWidget(pending)
        pending.setParent(None)
        pending.deleteLater()

        card.delete_requested.connect(lambda c=card: self._remove_card(c))
        self._cards_layout.insertWidget(idx, card)
        self._cards.append(card)
        # History-Tab nachladen falls offen
        if hasattr(self, "_history_view"):
            self._history_view.refresh()

    def _remove_pending(self, pending: PendingCard) -> None:
        pending.stop()
        self._cards_layout.removeWidget(pending)
        pending.setParent(None)
        pending.deleteLater()
        if not self._cards:
            self._empty_hint.show()

    def _remove_card(self, card: ResultCard) -> None:
        """Entfernt eine Card aus der UI und raeumt Quarantaene auf."""
        if card not in self._cards:
            return
        self._cards.remove(card)
        self._service.delete(card._result)  # noqa: SLF001 — interne Member-Lesung erlaubt
        self._cards_layout.removeWidget(card)
        card.setParent(None)
        card.deleteLater()
        if not self._cards:
            self._empty_hint.show()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """Wird vom App-Lifecycle aufgerufen — raeumt Quarantaene auf.

        Stoppt ausserdem alle noch laufenden ScanWorker-Threads.
        """
        for worker in self._workers:
            if worker.isRunning():
                worker.requestInterruption()
                worker.quit()
                worker.wait(2000)
        self._service.shutdown()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_style(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QWidget {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QLabel#DocumentScannerTitle {{"
            f"  color: {c.TEXT_MAIN}; font-size: 18px; font-weight: bold;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QLabel#DocumentScannerInfo {{"
            f"  color: {c.TEXT_DIM}; font-size: 12px;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QLabel#DocumentScannerEmptyHint {{"
            f"  color: {c.TEXT_DIM}; font-size: 12px;"
            f"  background: transparent; border: none;"
            f"  padding: 32px;"
            f"}}"
            f"QScrollArea {{ background: transparent; border: none; }}"
        )
