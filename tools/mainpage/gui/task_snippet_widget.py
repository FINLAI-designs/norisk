"""
task_snippet_widget — Kompaktes „Meine Aufgaben"-Snippet für den Homescreen.

 AP3 (2026-06-11, Option A): Zeigt die offenen und laufenden Tasks
aus dem Kanban-Board (``TaskService.get_board_data``) als schlanke
2-Spalten-Liste direkt auf dem Homescreen — bisher lagen die Aufgaben
unsichtbar hinter dem eingeklappten Akkordeon im NoRisk-Dashboard.

Bewusst KEIN eingebettetes ``TaskboardWidget``: Drag&Drop und Verwaltung
gehören ins Board; das Snippet ist eine priorisierte Lese-Sicht mit
Absprung „Alle im Board →". Wird mit dem Cockpit 3c)
zur Dringend-Liste weiterentwickelt.

Signals:
    board_requested: Klick auf „Alle im Board →".

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from core.widgets.button_styles import link_button_qss

if TYPE_CHECKING:
    from tools.mainpage.application.task_service import TaskService

_log = get_logger(__name__)

# Maximal sichtbare Einträge pro Spalte — mehr verdichtet nur, statt zu
# informieren (Smashing-Regel ~5 Elemente pro Bereich); Rest als Zähler.
_MAX_PRO_SPALTE = 6

# Sortier-Rang der Task-Prioritäten (hoch zuerst).
_PRIORITY_RANG = {"high": 0, "normal": 1, "low": 2}

# Marker-Symbol pro Priorität (Text, kein Icon-Font nötig).
_PRIORITY_MARKER = {"high": "!", "normal": "•", "low": "·"}


class TaskSnippetWidget(QWidget):
    """Lese-Snippet der offenen/laufenden Kanban-Aufgaben.

    Args:
        task_service: ``TaskService``-Instanz (geteilt mit dem Board).
        parent: Optionales Eltern-Widget.

    Signals:
        board_requested: Nutzer will zum vollständigen Board springen.
    """

    board_requested = Signal()

    def __init__(
        self, task_service: TaskService, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._tasks = task_service
        t = theme.get()
        self.setStyleSheet(
            f"background-color: {t.CARD_BG}; "
            f"border: 1px solid {t.BORDER}; border-radius: 4px;"
        )
        # Mindesthoehe, damit die Akkordeon-Sektion das Snippet nicht auf einen
        # unlesbaren Streifen druckt — Platz fuer Kopf + beide Spalten (bis
        # _MAX_PRO_SPALTE Zeilen + "+N weitere"). Sonst kollabiert der innere
        # QScrollArea-sizeHint die Sektion (Patrick: "zu schmal, kaum lesbar").
        self.setMinimumHeight(220)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 8, 12, 8)
        outer.setSpacing(6)

        # Kopfzeile: Titel + Board-Link
        hdr_row = QHBoxLayout()
        self._header_lbl = QLabel("Meine Aufgaben")
        self._header_lbl.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 13px; font-weight: bold; color: {t.ACCENT}; "
            f"background: transparent; border: none;"
        )
        hdr_row.addWidget(self._header_lbl)
        hdr_row.addStretch()

        self._btn_board = QPushButton("Alle im Board →")
        self._btn_board.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_board.setStyleSheet(link_button_qss())
        self._btn_board.clicked.connect(self.board_requested)
        hdr_row.addWidget(self._btn_board)
        outer.addLayout(hdr_row)

        # Scrollbarer 2-Spalten-Bereich (Offen | In Arbeit)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none; background: transparent;")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        cols = QHBoxLayout(content)
        cols.setContentsMargins(0, 0, 0, 0)
        cols.setSpacing(16)

        self._col_offen = QVBoxLayout()
        self._col_offen.setSpacing(4)
        self._col_arbeit = QVBoxLayout()
        self._col_arbeit.setSpacing(4)
        cols.addLayout(self._col_offen, stretch=1)
        cols.addLayout(self._col_arbeit, stretch=1)

        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

        self.refresh()
        theme.register_listener(self.apply_theme)

    # ------------------------------------------------------------------
    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"background-color: {c.CARD_BG}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px;"
        )
        self._header_lbl.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 13px; font-weight: bold; color: {c.ACCENT}; "
            f"background: transparent; border: none;"
        )
        self._btn_board.setStyleSheet(link_button_qss())
        self.refresh()

    def refresh(self) -> None:
        """Lädt das Board neu und baut beide Spalten auf."""
        try:
            board = self._tasks.get_board_data()
        except Exception as exc:  # noqa: BLE001 -- Homescreen darf nie crashen
            # Nur den Typ loggen — Exception-Texte koennen Pfade/Daten tragen.
            _log.warning(
                "TaskSnippet-Refresh fehlgeschlagen: %s", type(exc).__name__
            )
            board = {"open": [], "in_progress": []}

        offen = _sortiert(board.get("open") or [])
        arbeit = _sortiert(board.get("in_progress") or [])

        self._fuelle_spalte(self._col_offen, "Offen", offen)
        self._fuelle_spalte(self._col_arbeit, "In Arbeit", arbeit)

    # ------------------------------------------------------------------
    def _fuelle_spalte(self, col: QVBoxLayout, titel: str, tasks: list) -> None:
        """Leert eine Spalte und füllt sie mit Kopf + Task-Zeilen.

        Args:
            col: Ziel-Layout der Spalte.
            titel: Spaltenüberschrift (ohne Zähler).
            tasks: Sortierte Task-Liste der Spalte.
        """
        t = theme.get()
        while col.count():
            item = col.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        kopf = QLabel(f"{titel} ({len(tasks)})")
        kopf.setStyleSheet(
            f"font-size: 11px; font-weight: bold; color: {t.TEXT_DIM}; "
            f"background: transparent; border: none;"
        )
        col.addWidget(kopf)

        if not tasks:
            leer = QLabel("Keine Aufgaben — gut so.")
            leer.setStyleSheet(
                f"font-size: 11px; color: {t.TEXT_DIM}; "
                f"background: transparent; border: none;"
            )
            col.addWidget(leer)
        else:
            for task in tasks[:_MAX_PRO_SPALTE]:
                col.addWidget(self._build_row(task))
            rest = len(tasks) - _MAX_PRO_SPALTE
            if rest > 0:
                mehr = QLabel(f"+ {rest} weitere im Board")
                mehr.setStyleSheet(
                    f"font-size: 11px; color: {t.TEXT_DIM}; "
                    f"background: transparent; border: none;"
                )
                col.addWidget(mehr)

        col.addStretch()

    def _build_row(self, task) -> QWidget:
        """Baut eine Task-Zeile (Prioritäts-Marker + Titel).

        Args:
            task: ``Task``-Domain-Objekt.

        Returns:
            QWidget der Zeile.
        """
        t = theme.get()
        row = QWidget()
        row.setStyleSheet("background: transparent; border: none;")
        lyt = QHBoxLayout(row)
        lyt.setContentsMargins(0, 1, 0, 1)
        lyt.setSpacing(6)

        prio = getattr(task, "priority", "normal")
        marker = QLabel(_PRIORITY_MARKER.get(prio, "•"))
        marker.setFixedWidth(10)
        marker_color = (
            theme.SEVERITY_SIGNAL_HIGH if prio == "high" else t.TEXT_DIM
        )
        marker.setStyleSheet(
            f"font-size: 12px; font-weight: bold; color: {marker_color}; "
            f"background: transparent; border: none;"
        )
        lyt.addWidget(marker)

        titel_text = str(getattr(task, "title", ""))
        if len(titel_text) > 70:
            titel_text = titel_text[:67] + "…"
        titel = QLabel(titel_text)
        # Task-Titel sind untrusted (KI-/User-generiert) — nie als
        # Auto-RichText rendern; Tooltips rendern HTML → escapen (R22).
        titel.setTextFormat(Qt.TextFormat.PlainText)
        titel.setStyleSheet(
            f"font-size: 12px; color: {t.TEXT_MAIN}; "
            f"background: transparent; border: none;"
        )
        titel.setToolTip(html.escape(str(getattr(task, "title", ""))))
        lyt.addWidget(titel, stretch=1)
        return row


def _sortiert(tasks: list) -> list:
    """Sortiert Tasks nach Priorität (high → normal → low).

    Args:
        tasks: Unsortierte Task-Liste.

    Returns:
        Neue, sortierte Liste.
    """
    return sorted(
        tasks,
        key=lambda t: _PRIORITY_RANG.get(getattr(t, "priority", "normal"), 1),
    )
