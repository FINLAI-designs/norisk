"""
section_organizational — Sektion 5: Organisatorische Sicherheit.

Vier Kacheln (DSGVO / Phishing / MFA / Passwort-Manager) in einem
``QGridLayout``. Unter 1000 px Containerbreite wechselt das Raster
von 4×1 auf 2×2. Bei fehlendem Assessment zeigt eine mittige CTA-Zeile
den Button ``"Assessment starten"`` — Klick emittiert das ``navigate``-
Signal mit dem Key ``"security_scoring"``.

Author: Patrick Riederich
Version: 0.2 (Phase 2)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import ICON_SIZE_SM, Icons, get_accent_icon
from tools.norisk_dashboard.domain.models import OrgSnapshot, OrgTile

_BREAKPOINT_PX = 1000

# FE-1 (Code-Review 2026-05-19): Material Symbols statt Emojis. Skill
# 'frontend-design' verlangt Google Material Icons als einziges
# Icon-System.
_TILE_ICON: dict[str, str] = {
    "dsgvo": Icons.SHIELD,
    "phishing": Icons.MAIL,
    "mfa": Icons.LOCK,
    "passwort_manager": Icons.KEY,
}


class OrganizationalSection(QWidget):
    """Container für die vier Org-Kacheln plus CTA-Zeile.

    Signals:
        navigate(str): Emittiert ``"security_scoring"`` beim CTA-Klick.
    """

    navigate = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        self._grid_host = QWidget(self)
        self._grid = QGridLayout(self._grid_host)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(10)
        root.addWidget(self._grid_host)

        self._tiles: dict[str, _OrgTileWidget] = {}

        self._cta_host = QWidget(self)
        cta_lay = QHBoxLayout(self._cta_host)
        cta_lay.setContentsMargins(0, 4, 0, 0)
        cta_lay.addStretch()

        self._cta_hint = QLabel(
            "Noch kein Assessment durchgeführt.", self._cta_host
        )
        self._cta_hint.setStyleSheet(
            f"color: {theme.get().TEXT_DIM}; font-size: 11px;"
        )
        cta_lay.addWidget(self._cta_hint)

        self._cta_btn = QPushButton("Assessment starten", self._cta_host)
        self._cta_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._cta_btn.setStyleSheet(
            f"QPushButton {{ background: {theme.DARK_ACCENT}; "
            f"color: {theme.get().BG_DARK}; border: 0; border-radius: 4px; "
            f"padding: 6px 14px; font-size: 12px; font-weight: bold; }} "
            f"QPushButton:hover {{ background: {theme.ACCENT_HOVER_BRIGHT}; }}"
        )
        self._cta_btn.clicked.connect(
            lambda: self.navigate.emit("security_scoring")
        )
        cta_lay.addWidget(self._cta_btn)
        cta_lay.addStretch()
        root.addWidget(self._cta_host)
        self._cta_host.setVisible(False)

        self._current_cols = 0  # gezwungen auf 4 im ersten resizeEvent

    def update_data(self, snapshot: OrgSnapshot | None) -> None:
        """Aktualisiert Kacheln + CTA anhand des Snapshots."""
        tiles = snapshot.tiles if snapshot else []
        has_assessment = bool(snapshot and snapshot.has_assessment)

        # Vorhandene Kacheln bereinigen, damit die Reihenfolge des Snapshots gilt
        while self._grid.count():
            item = self._grid.takeAt(0)
            w = item.widget() if item else None
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        self._tiles.clear()

        for tile in tiles:
            w = _OrgTileWidget(tile, self._grid_host)
            self._tiles[tile.key] = w

        self._relayout(self._compute_cols())
        self._cta_host.setVisible(not has_assessment)

    def resizeEvent(self, event) -> None:  # noqa: ANN001
        super().resizeEvent(event)
        self._relayout(self._compute_cols())

    def _compute_cols(self) -> int:
        return 4 if self.width() >= _BREAKPOINT_PX else 2

    def _relayout(self, cols: int) -> None:
        if cols == self._current_cols and self._grid.count() == len(self._tiles):
            return
        # Aus dem Grid entfernen (ohne Delete)
        for w in self._tiles.values():
            self._grid.removeWidget(w)
        self._current_cols = cols
        for idx, w in enumerate(self._tiles.values()):
            r, c = divmod(idx, cols)
            self._grid.addWidget(w, r, c)


class _OrgTileWidget(QFrame):
    """Einzelne Kachel — Icon + Name + Score + Mini-Progressbar."""

    def __init__(self, tile: OrgTile, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tile = tile
        c = theme.get()
        self.setObjectName("orgTile")
        self.setStyleSheet(
            f"#orgTile {{ background: {c.CARD_BG}; "
            f"border: 1px solid {c.BORDER}; border-radius: 6px; }}"
        )
        self.setFixedHeight(110)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(2)

        top = QHBoxLayout()
        top.setSpacing(6)
        icon = QLabel(self)
        icon.setPixmap(
            get_accent_icon(_TILE_ICON.get(tile.key, Icons.CIRCLE)).pixmap(
                ICON_SIZE_SM, ICON_SIZE_SM
            )
        )
        top.addWidget(icon)
        name = QLabel(tile.label, self)
        name.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 11px; font-weight: bold;"
        )
        top.addWidget(name)
        top.addStretch()
        lay.addLayout(top)

        score_text = "–" if tile.score is None else f"{tile.score:.0f}"
        self._score = QLabel(score_text, self)
        self._score.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 30px; font-weight: bold;"
        )
        self._score.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._score, stretch=1)

        self._bar = _MiniBar(tile.score, self)
        lay.addWidget(self._bar)

        if tile.score is not None and tile.findings_open > 0:
            footnote = QLabel(
                f"{tile.findings_open} Kriterien offen", self
            )
            footnote.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 10px;")
            footnote.setAlignment(Qt.AlignmentFlag.AlignRight)
            lay.addWidget(footnote)


class _MiniBar(QWidget):
    """4-px-Progressbar mit Gradient-Fill (rot → gelb → grün)."""

    def __init__(self, score: float | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score = score
        self.setFixedHeight(4)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

    def paintEvent(self, event) -> None:  # noqa: ANN001
        from tools.norisk_dashboard.gui.breakdown_bars import _gradient_color

        painter = QPainter(self)
        c = theme.get()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(c.BG_BUTTON_DISABLED))
        painter.drawRoundedRect(self.rect(), 2, 2)

        if self._score is None:
            painter.end()
            return
        s = max(0.0, min(100.0, float(self._score)))
        w = int(self.width() * s / 100.0)
        if w > 0:
            painter.setBrush(_gradient_color(s))
            painter.drawRoundedRect(0, 0, w, self.height(), 2, 2)
        painter.end()
