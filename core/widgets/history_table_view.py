"""history_table_view — Generische Tabellen-Ansicht fuer "Verlauf"-Listen.

Gemeinsame Basis fuer Historien-Widgets (Patch-Upgrade-Verlauf, Dokument-Scan-
Verlauf,...): Titel + "Aktualisieren"-Button + ``QTableWidget`` + Empty-State +
theme-aware QSS + fail-safe ``list_recent``-Read. Unterklassen konfigurieren
``COL_HEADERS`` / ``STRETCH_COLS`` / ``TITLE`` / ``EMPTY_HINT`` / ``_NAME`` und
implementieren ``_fill_row`` (Zell-Befuellung pro Zeile).

Das Repository wird per Constructor-Injection gereicht (Hex-Architektur-Vertrag;
die GUI haengt nicht direkt am data-Layer). Ist kein Repository injiziert, bleibt
die Tabelle leer.

Schichtzugehoerigkeit: core/widgets/ — tool-unabhaengig, wiederverwendbar.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger

_log = get_logger(__name__)


class HistoryTableView(QWidget):
    """Basis-Widget fuer eine read-only Verlaufs-Tabelle aus einem Repository.

    Unterklassen setzen die Klassen-Attribute und implementieren
:meth:`_fill_row`. Der Refresh liest ``repository.list_recent(limit=200)``
    fail-safe und blendet einen Empty-State ein, wenn nichts vorhanden ist.
    """

    #: Spalten-Ueberschriften (Unterklasse setzt sie).
    COL_HEADERS: tuple[str, ...] = ()
    #: Spalten-Indizes, die den freien Platz fuellen (Rest: ResizeToContents).
    STRETCH_COLS: tuple[int, ...] = (1,)
    #: Titel ueber der Tabelle.
    TITLE: str = "Verlauf"
    #: Hinweis, wenn keine Eintraege vorhanden sind.
    EMPTY_HINT: str = "Noch keine Eintraege in der Datenbank."
    #: objectName-Praefix fuers self-contained QSS (z.B. "History").
    _NAME: str = "History"

    def __init__(self, repository=None, parent: QWidget | None = None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self._repository = repository
        self._build_ui()
        self.refresh()
        theme.register_listener(self._apply_style)
        self._apply_style()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(8)
        title = QLabel(self.TITLE)
        title.setObjectName(f"{self._NAME}Title")
        head.addWidget(title, stretch=1)

        self._refresh_btn = QPushButton("Aktualisieren")
        self._refresh_btn.setObjectName(f"{self._NAME}RefreshBtn")
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.clicked.connect(self.refresh)
        head.addWidget(self._refresh_btn)
        layout.addLayout(head)

        self._table = QTableWidget(0, len(self.COL_HEADERS))
        self._table.setHorizontalHeaderLabels(list(self.COL_HEADERS))
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        header = self._table.horizontalHeader()
        stretch = set(self.STRETCH_COLS)
        for col in range(len(self.COL_HEADERS)):
            mode = (
                QHeaderView.ResizeMode.Stretch
                if col in stretch
                else QHeaderView.ResizeMode.ResizeToContents
            )
            header.setSectionResizeMode(col, mode)
        layout.addWidget(self._table, stretch=1)

        self._empty_hint = QLabel(self.EMPTY_HINT)
        self._empty_hint.setObjectName(f"{self._NAME}EmptyHint")
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._empty_hint)

    def refresh(self) -> None:
        """Liest die aktuellen N Eintraege und repopuliert die Tabelle (fail-safe)."""
        entries: list = []
        if self._repository is not None:
            try:
                entries = self._repository.list_recent(limit=200)
            except Exception as exc:  # noqa: BLE001 -- History darf den UI-Refresh nie crashen
                _log.warning("History-Repo-Read fehlgeschlagen: %s", exc)
                entries = []

        self._table.setRowCount(0)
        self._table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            self._fill_row(row, entry)

        self._empty_hint.setVisible(len(entries) == 0)
        self._table.setVisible(len(entries) > 0)

    def _fill_row(self, row: int, entry) -> None:  # type: ignore[no-untyped-def]
        """Fuellt Tabellenzeile ``row`` aus ``entry`` — Unterklasse implementiert."""
        raise NotImplementedError

    def _apply_style(self) -> None:
        c = theme.get()
        n = self._NAME
        self.setStyleSheet(
            f"QLabel#{n}Title {{"
            f"  color: {c.TEXT_MAIN}; font-size: 14px; font-weight: bold;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QPushButton#{n}RefreshBtn {{"
            f"  background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f"  border: 1px solid {c.BORDER}; border-radius: 4px;"
            f"  padding: 4px 12px; font-size: 12px;"
            f"}}"
            f"QPushButton#{n}RefreshBtn:hover {{"
            f"  background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f"  border-color: {c.ACCENT};"
            f"}}"
            f"QLabel#{n}EmptyHint {{"
            f"  color: {c.TEXT_DIM}; font-size: 12px;"
            f"  background: transparent; border: none; padding: 32px;"
            f"}}"
            f"QTableWidget {{"
            f"  background: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f"  border: 1px solid {c.BORDER}; gridline-color: {c.BORDER};"
            f"}}"
            f"QHeaderView::section {{"
            f"  background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN};"
            f"  border: 1px solid {c.BORDER}; padding: 4px;"
            f"}}"
        )
