"""
section_cves_scans — Sektion 3: CVE-Liste + Scan-Status (Heatmap).

Zwei-Spalten-Layout:
- Links: techstack-gefilterte CVE-Liste (scrollbar)
- Rechts: Heatmap (Tool × Tag) letzte 14 Tage

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.norisk_dashboard.domain.models import CveListEntry, ScanEntry
from tools.norisk_dashboard.gui.heatmap_widget import HeatmapWidget


class CvesScansSection(QWidget):
    """CVE-Liste links, Heatmap rechts.

    Signals:
        cve_clicked(str): Klick auf eine CVE-Zeile (Payload: CVE-ID).

    Die Heatmap rechts ist rein informativ (kein Klick-Deep-Link).
    """

    cve_clicked = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        # Links: CVE-Liste
        self._cve_container = _CveListContainer(self)
        self._cve_container.cve_clicked.connect(self.cve_clicked.emit)
        root.addWidget(self._cve_container, stretch=1)

        # Rechts: Heatmap (rein informativ — kein Klick-Deep-Link)
        self._scan_container = _ScanHeatmapContainer(self)
        root.addWidget(self._scan_container, stretch=1)

    def update_data(
        self,
        cves: list[CveListEntry],
        scans: list[ScanEntry],
    ) -> None:
        """Aktualisiert beide Spalten."""
        self._cve_container.update_data(cves)
        self._scan_container.update_data(scans)


class _CveListContainer(QFrame):
    """Linke Spalte: Titelzeile + scrollbare CVE-Liste."""

    cve_clicked = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        c = theme.get()
        self.setObjectName("cveListContainer")
        self.setStyleSheet(
            f"#cveListContainer {{ background: {c.BG_MAIN}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; }}"
        )

        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(6)

        title = QLabel("Relevante CVEs (techstack-gefiltert)", self)
        title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold;"
        )
        lay.addWidget(title)

        self._scroll = QScrollArea(self)
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setMinimumHeight(180)
        lay.addWidget(self._scroll, stretch=1)

        self._list_host = QWidget()
        self._list_layout = QVBoxLayout(self._list_host)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(4)
        self._list_layout.addStretch()
        self._scroll.setWidget(self._list_host)

    def update_data(self, cves: list[CveListEntry]) -> None:
        # Bestehende Rows entfernen (aber Stretch-Item am Ende erhalten)
        while self._list_layout.count() > 1:
            item = self._list_layout.takeAt(0)
            w = item.widget() if item else None
            if w is not None:
                w.deleteLater()

        if not cves:
            empty = QLabel("Keine relevanten CVEs.", self._list_host)
            empty.setStyleSheet(
                f"color: {theme.get().TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._list_layout.insertWidget(0, empty)
            return

        for cve in cves:
            row = _CveRow(cve, self._list_host)
            row.clicked.connect(self.cve_clicked.emit)
            self._list_layout.insertWidget(
                self._list_layout.count() - 1, row
            )


class _CveRow(QFrame):
    """Eine Zeile in der CVE-Liste. Klickbar — emittiert ``clicked(cve_id)``."""

    clicked = Signal(str)

    def __init__(self, cve: CveListEntry, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        c = theme.get()
        self._cve_id = cve.cve_id
        self.setObjectName("cveRow")
        self.setStyleSheet(
            f"#cveRow {{ background: {c.CARD_BG}; "
            f"border: 1px solid {c.BORDER}; border-radius: 3px; }} "
            f"#cveRow:hover {{ border-color: {theme.DARK_ACCENT}; }}"
        )
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"Details zu {cve.cve_id} im CSAF-Advisor öffnen")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 6, 8, 6)
        lay.setSpacing(2)

        top = QHBoxLayout()
        top.setSpacing(8)
        id_label = QLabel(cve.cve_id, self)
        id_label.setStyleSheet(
            f"color: {theme.DARK_ACCENT}; font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: bold;"
        )
        top.addWidget(id_label)

        if cve.product:
            prod = QLabel(cve.product, self)
            prod.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_CAPTION}px;")
            top.addWidget(prod)

        top.addStretch()
        date_label = QLabel(f"{cve.published:%d.%m.%Y}", self)
        date_label.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION_XS}px;")
        top.addWidget(date_label)
        lay.addLayout(top)

        if cve.description:
            desc = QLabel(cve.description, self)
            desc.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_CAPTION}px;")
            desc.setWordWrap(True)
            lay.addWidget(desc)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._cve_id)
        super().mousePressEvent(event)


class _ScanHeatmapContainer(QFrame):
    """Rechte Spalte: Titelzeile + Heatmap + Legende (rein informativ)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        c = theme.get()
        self.setObjectName("scanHeatmapContainer")
        self.setStyleSheet(
            f"#scanHeatmapContainer {{ background: {c.BG_MAIN}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; }}"
        )

        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(6)

        title = QLabel("Scan-Status (letzte 14 Tage)", self)
        title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold;"
        )
        lay.addWidget(title)

        self._heatmap = HeatmapWidget(self)
        lay.addWidget(self._heatmap, stretch=1)

        lay.addWidget(_Legend(self))

    def update_data(self, scans: list[ScanEntry]) -> None:
        self._heatmap.update_data(scans, days=14)


class _Legend(QWidget):
    """Farb-Legende für die Heatmap."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        c = theme.get()
        for label, color in (
            ("OK", theme.DARK_ACCENT),
            ("Warnung", theme.GRADE_MID_AMBER),
            ("Fehler", c.DANGER),
            ("Kein Scan", c.BG_BUTTON_DISABLED),
        ):
            box = QLabel(self)
            box.setFixedSize(10, 10)
            box.setStyleSheet(f"background: {color}; border-radius: 2px;")
            lay.addWidget(box)
            text = QLabel(label, self)
            text.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION_XS}px;")
            lay.addWidget(text)
        lay.addStretch()
