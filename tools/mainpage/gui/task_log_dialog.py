"""
task_log_dialog — Aufgabenlog des Task-Boards.

Read-only-Historie aller erledigten und abgelehnten Aufgaben: Datum,
Titel, Status (Erledigt / Automatisch erledigt / Abgelehnt), Quelle
(KI-Tool vs. Manuell) und Notiz (Auto-Erledigt-Begründung bzw.
Ablehnungs-Begründung). Ergänzt die ERLEDIGT-Spalte des Boards, die
bewusst nur den heutigen Tag zeigt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import ICON_SIZE_DIALOG, Icons, get_icon
from core.logger import get_logger
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.domain.models import Task

# Geteiltes Feld-Styling der Schwester-Dialoge (kein Drift-Review).
from tools.mainpage.gui.task_dialogs import _combo_css

_log = get_logger(__name__)

_COLUMNS = ("Datum", "Titel", "Status", "Quelle", "Notiz")

# Filter-Einträge: Label -> Prädikat-Schlüssel.
_FILTER_ALL = "Alle"
_FILTER_DONE = "Erledigt"
_FILTER_AUTO = "Automatisch erledigt"
_FILTER_DISMISSED = "Abgelehnt"


def _status_label(task: Task) -> str:
    """Gibt das Anzeige-Label für den Historien-Status zurück."""
    if task.status == "dismissed":
        return _FILTER_DISMISSED
    if task.done_note:
        return _FILTER_AUTO
    return _FILTER_DONE


def _date_label(task: Task) -> str:
    """Formatiert den Historien-Zeitpunkt in lokaler Zeit.

    ``done_at`` (UTC) hat Vorrang; abgelehnte Tasks haben keins —
    dann greift ``updated_at``.
    """
    raw = task.done_at or task.updated_at
    if not raw:
        return "—"
    try:
        return (
            datetime.fromisoformat(raw).astimezone().strftime("%d.%m.%Y %H:%M")
        )
    except ValueError:
        return raw


class TaskLogDialog(QDialog):
    """Modaler Aufgabenlog-Dialog (read-only).

    Args:
        task_service: Service für:meth:`TaskService.get_task_log`.
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        task_service: TaskService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._svc = task_service
        self._tasks: list[Task] = []
        self.setWindowTitle("Aufgabenlog")
        self.setMinimumSize(700, 480)
        self.setModal(True)
        self._build_ui()
        self._load()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def _build_ui(self) -> None:
        """Erstellt die Dialog-Oberfläche."""
        t = theme.get()

        lyt = QVBoxLayout(self)
        lyt.setSpacing(12)
        lyt.setContentsMargins(20, 16, 20, 16)

        header = QHBoxLayout()
        header.setSpacing(10)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            get_icon(Icons.HISTORY, color=t.ACCENT).pixmap(
                ICON_SIZE_DIALOG, ICON_SIZE_DIALOG
            )
        )
        header.addWidget(icon_lbl)
        self._title_lbl = QLabel("Aufgabenlog")
        header.addWidget(self._title_lbl)
        header.addStretch()

        self._filter_box = QComboBox()
        self._filter_box.addItems(
            [_FILTER_ALL, _FILTER_DONE, _FILTER_AUTO, _FILTER_DISMISSED]
        )
        self._filter_box.currentTextChanged.connect(
            lambda _text: self._render()
        )
        header.addWidget(self._filter_box)
        lyt.addLayout(header)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._table.setAlternatingRowColors(True)
        hdr = self._table.horizontalHeader()
        # Titel-Spalte streckt, der Rest passt sich dem Inhalt an.
        for col in range(len(_COLUMNS)):
            hdr.setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        lyt.addWidget(self._table, 1)

        self._count_lbl = QLabel("")
        lyt.addWidget(self._count_lbl)

        self.apply_theme()

    # ------------------------------------------------------------------
    # Daten
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Lädt die Historie aus dem Service und rendert die Tabelle."""
        try:
            self._tasks = self._svc.get_task_log()
        except Exception as exc:  # noqa: BLE001 -- Log-Anzeige darf UI nicht crashen
            _log.error("Aufgabenlog konnte nicht geladen werden: %s", exc)
            self._tasks = []
        self._render()

    def _filtered(self) -> list[Task]:
        """Wendet den aktiven Status-Filter clientseitig an."""
        selected = self._filter_box.currentText()
        if selected == _FILTER_ALL:
            return self._tasks
        return [t for t in self._tasks if _status_label(t) == selected]

    def _render(self) -> None:
        """Befüllt die Tabelle aus dem gefilterten Bestand."""
        rows = self._filtered()
        self._table.setRowCount(len(rows))
        for row, task in enumerate(rows):
            note = task.done_note or task.dismissed_reason
            source = (
                f"KI — {task.source_tool}" if task.source == "auto" else "Manuell"
            )
            cells = (
                _date_label(task),
                task.title,
                _status_label(task),
                source,
                note,
            )
            for col, value in enumerate(cells):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self._table.setItem(row, col, item)
        self._count_lbl.setText(f"{len(rows)} Einträge")

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
        )
        self._title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px; "
            f"font-weight: 700; color: {c.TEXT_MAIN}; background: transparent; "
            f"border: none;"
        )
        self._count_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_CAPTION}px; "
            f"color: {c.TEXT_DIM}; background: transparent; border: none;"
        )
        self._filter_box.setStyleSheet(_combo_css(c))
