"""
dropzone_widget — Drag&Drop-Zone fuer den Document Scanner.

Diskreter Bereich der Drag&Drop akzeptiert. Wenn der User eine Datei
(oder mehrere) ueber das Widget zieht, wechselt die Optik in einen
Hover-Zustand. Auf Drop emittiert das Widget ``file_dropped(Path)``
fuer jede Datei.

Drag-OUT ist deaktiviert — der User soll Dateien aus der Quarantaene
NICHT zurueck ins OS ziehen koennen. Dafuer gibt es den expliziten
"Speichern unter..."-Button im Result-Widget.

Schichtzugehoerigkeit: gui/ — darf application/, core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDropEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from core import theme
from core.icons import ICON_SIZE_XL, get_icon


class DropzoneWidget(QFrame):
    """Drag&Drop-Zielzone mit Hover-Visualisierung.

    Signals:
        file_dropped(Path): Wird fuer jede abgelegte Datei einmal
            emittiert. Bei Drop von 3 Dateien feuert das Signal 3 Mal.
    """

    file_dropped = Signal(Path)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("DocumentScannerDropzone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(180)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Material-Symbol "description" (= Dokument-Icon) statt Emoji —
        # R2-Compliance (Coding-Rules-Backlog 2026-05-17).
        self._icon_label = QLabel()
        self._icon_label.setObjectName("DropzoneIcon")
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_label.setPixmap(
            get_icon("description", color=theme.DARK_ACCENT).pixmap(
                QSize(ICON_SIZE_XL, ICON_SIZE_XL)
            )
        )

        self._title_label = QLabel(
            "Datei oder E-Mail-Anhang hierhin ziehen\n"
            "oder klicken zum Auswaehlen"
        )
        self._title_label.setObjectName("DropzoneTitle")
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title_label.setWordWrap(True)

        self._hint_label = QLabel(
            "Office  |  PDF  |  Archive  |  Skripte  |  Bilder/SVG"
        )
        self._hint_label.setObjectName("DropzoneHint")
        self._hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._browse_btn = QPushButton("Datei auswaehlen ...")
        self._browse_btn.setObjectName("DropzoneBrowse")
        self._browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._browse_btn.clicked.connect(self._open_file_dialog)

        layout.addWidget(self._icon_label)
        layout.addWidget(self._title_label)
        layout.addWidget(self._hint_label)
        layout.addWidget(self._browse_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        self._apply_style(hover=False)
        theme.register_listener(lambda: self._apply_style(hover=False))

    # ------------------------------------------------------------------
    # Drag&Drop-Handler
    # ------------------------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802 — Qt-API
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._apply_style(hover=True)
        else:
            event.ignore()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:  # noqa: N802 — Qt-API
        self._apply_style(hover=False)
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802 — Qt-API
        self._apply_style(hover=False)
        urls = event.mimeData().urls()
        emitted = 0
        for url in urls:
            if not url.isLocalFile():
                continue
            local_path = Path(url.toLocalFile())
            if local_path.is_file():
                self.file_dropped.emit(local_path)
                emitted += 1
        if emitted:
            event.acceptProposedAction()
        else:
            event.ignore()

    # ------------------------------------------------------------------
    # File-Dialog-Fallback
    # ------------------------------------------------------------------

    def _open_file_dialog(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Datei(en) zum Scannen auswaehlen",
            "",
            "Alle Dateien (*.*)",
        )
        for f in files:
            self.file_dropped.emit(Path(f))

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------

    def _apply_style(self, *, hover: bool) -> None:
        c = theme.get()
        border_color = c.ACCENT if hover else c.BORDER
        bg_color = c.BG_BUTTON if hover else c.CARD_BG
        self.setStyleSheet(
            f"QFrame#DocumentScannerDropzone {{"
            f"  background-color: {bg_color};"
            f"  border: 2px dashed {border_color};"
            f"  border-radius: 8px;"
            f"}}"
            f"QLabel#DropzoneIcon {{"
            f"  font-size: 36px; background: transparent; border: none;"
            f"}}"
            f"QLabel#DropzoneTitle {{"
            f"  color: {c.TEXT_MAIN}; font-size: 13px; font-weight: bold;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QLabel#DropzoneHint {{"
            f"  color: {c.TEXT_DIM}; font-size: 11px;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QPushButton#DropzoneBrowse {{"
            f"  background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f"  border: 1px solid {c.BORDER}; border-radius: 4px;"
            f"  padding: 6px 16px; font-size: 12px;"
            f"}}"
            f"QPushButton#DropzoneBrowse:hover {{"
            f"  background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f"  border-color: {c.ACCENT};"
            f"}}"
        )
