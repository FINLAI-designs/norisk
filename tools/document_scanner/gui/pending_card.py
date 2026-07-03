"""
pending_card — Platzhalter-Karte waehrend ein Scan laeuft.

Wird vom:class:`DocumentScannerWidget` direkt nach dem Drop angezeigt
und bei ``ScanWorker.finished`` durch eine:class:`ResultCard` ersetzt.

Schichtzugehoerigkeit: gui/ — darf application/, core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout

from core import theme


class PendingCard(QFrame):
    """Karte mit Spinner-Text-Animation waehrend ein Scan laeuft."""

    def __init__(self, source: Path, parent=None) -> None:
        super().__init__(parent)
        self._source = source
        self.setObjectName("DocumentScannerPendingCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(4)

        header = QHBoxLayout()
        self._name_lbl = QLabel(source.name)
        self._name_lbl.setObjectName("PendingName")
        header.addWidget(self._name_lbl, stretch=1)

        self._spinner_lbl = QLabel("Scan laeuft…")
        self._spinner_lbl.setObjectName("PendingSpinner")
        header.addWidget(self._spinner_lbl)
        outer.addLayout(header)

        self._hint_lbl = QLabel(
            "Datei wird kopiert, der Typ wird ueber Magika erkannt und "
            "die Inhalte werden statisch geprueft."
        )
        self._hint_lbl.setObjectName("PendingHint")
        self._hint_lbl.setWordWrap(True)
        outer.addWidget(self._hint_lbl)

        self._dot_count = 0
        self._timer = QTimer(self)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

        self._apply_style()
        theme.register_listener(self._apply_style)

    def stop(self) -> None:
        """Stoppt die Spinner-Animation (vor dem Entfernen)."""
        self._timer.stop()

    def _tick(self) -> None:
        self._dot_count = (self._dot_count + 1) % 4
        dots = "." * self._dot_count
        self._spinner_lbl.setText(f"Scan laeuft{dots}")

    def _apply_style(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QFrame#DocumentScannerPendingCard {{"
            f"  background-color: {c.CARD_BG};"
            f"  border: 1px dashed {c.ACCENT}; border-radius: 6px;"
            f"}}"
            f"QLabel#PendingName {{"
            f"  color: {c.TEXT_MAIN}; font-size: 13px; font-weight: bold;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QLabel#PendingSpinner {{"
            f"  color: {c.ACCENT}; font-size: 12px;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QLabel#PendingHint {{"
            f"  color: {c.TEXT_DIM}; font-size: 11px;"
            f"  background: transparent; border: none;"
            f"}}"
        )

    def alignment(self) -> int:
        return Qt.AlignmentFlag.AlignTop
