"""
taskboard_widget — Kanban-Board-Widget des Mainpage-Dashboards.

Zeigt offene, laufende und heute erledigte Aufgaben in drei Spalten.
Unterstützt Drag-and-Drop zwischen Spalten, Bearbeiten und Löschen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QMimeData, Qt, Signal
from PySide6.QtGui import QAction, QActionGroup, QDrag
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QScrollArea,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.button_styles import (
    card_menu_button_qss,
    menu_qss,
    outline_button_qss,
    primary_button_qss,
    toolbar_button_qss,
)
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.domain.models import Task
from tools.mainpage.gui.task_dialogs import DismissTaskDialog, TaskFormDialog

_log = get_logger(__name__)

_TASK_MIME = "application/x-finlai-task"

# Kategorie → Farbe ("tool" fehlt bewusst → Fallback t.ACCENT)
# Hinweis: "klient" nutzt #ffb86c (Pfirsich-Ton, leicht heller als
# theme.DARK_WARNING="#FFB74D" — Hue-Verschiebung ~3°). Bewusst literal,
# weil Mapping eine sichtbare Verschiebung wäre.
_CATEGORY_COLORS: dict[str, str] = {
    "klient": "#ffb86c",  # noqa: warning-peach-variant
    "allgemein": theme.SEVERITY_SIGNAL_INFO,
}

# Priorität → linker Rand-Farbe ("normal" fehlt bewusst → Fallback t.ACCENT)
_PRIORITY_COLORS: dict[str, str] = {
    "high": theme.SEVERITY_SIGNAL_CRITICAL,
    "low": theme.SEVERITY_SIGNAL_INFO,
}

# Sprint S2b — KI-Todo Urgency-Badge-Spezifikation (AI_TODO 5.5).
# Drei Effort-Klassen mit eigener Farbe + kurzem Badge-Text + Tooltip.
_URGENCY_COLORS: dict[str, str] = {
    "quick": theme.WARNING_ORANGE,
    "mittel": theme.DARK_STATUS_INFO,
    "langfrist": theme.DARK_TEXT_SECONDARY,
}
_URGENCY_LABELS: dict[str, str] = {
    "quick": "QUICK",
    "mittel": "WOCHE",
    "langfrist": "LANGFRIST",
}
_URGENCY_TOOLTIPS: dict[str, str] = {
    "quick": "Quick — heute machbar",
    "mittel": "Mittel — diese Woche",
    "langfrist": "Langfristig — strategisch",
}

# KI-Indikator-Border-Breite (linker Rand) für Auto-Tasks.
_KI_BORDER_WIDTH_PX = 3


# ---------------------------------------------------------------------------
# Dialoge: TaskFormDialog + DismissTaskDialog leben in task_dialogs.py
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Drag-and-Drop Ziel-Widget
# ---------------------------------------------------------------------------


class _DropTarget(QWidget):
    """QWidget das Task-Drag-and-Drop akzeptiert."""

    task_dropped = Signal(str)  # task_id

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasFormat(_TASK_MIME):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        if event.mimeData().hasFormat(_TASK_MIME):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        if event.mimeData().hasFormat(_TASK_MIME):
            task_id = bytes(event.mimeData().data(_TASK_MIME)).decode()
            self.task_dropped.emit(task_id)
            event.acceptProposedAction()
        else:
            event.ignore()


# ---------------------------------------------------------------------------
# _TaskCard
# ---------------------------------------------------------------------------


class _TaskCard(QFrame):
    """Karte für eine einzelne Aufgabe im Kanban-Board.

    Unterstützt Drag-and-Drop zum Verschieben zwischen Spalten. Eine
    lesbare Hauptaktion treibt den Status vorwärts (Offen → In Arbeit →
    Erledigt); alle weiteren Aktionen (Status-Auswahl, Bearbeiten,
    Ablehnen, Löschen, KI-Feedback) liegen im "⋯"-Menü.
    """

    def __init__(
        self,
        task: Task,
        task_service: TaskService,
        on_refresh,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._task = task
        self._svc = task_service
        self._on_refresh = on_refresh
        self._drag_start_pos = None

        t = theme.get()
        # Sprint S2b: Auto-Tasks (KI-Todos) bekommen einen breiten
        # ``STATUS_INFO``-Border, damit sie auf einen Blick von manuellen
        # Tasks unterscheidbar sind (AI_TODO 5.4).
        is_ki = task.source == "auto"
        if is_ki:
            border_color = t.STATUS_INFO
            border_width = _KI_BORDER_WIDTH_PX
        else:
            border_color = _PRIORITY_COLORS.get(task.priority, t.ACCENT)
            border_width = _KI_BORDER_WIDTH_PX
        self.setStyleSheet(
            f"QFrame {{ "
            f"background: {t.CARD_BG}; "
            f"border: 1px solid {t.BORDER}; "
            f"border-left: {border_width}px solid {border_color}; "
            f"border-radius: 4px; "
            f"margin: 2px; "
            f"}}"
            f"QFrame:hover {{ border-color: {t.ACCENT}; "
            f"border-left-color: {border_color}; }}"
        )
        self.setCursor(Qt.CursorShape.OpenHandCursor)

        lyt = QVBoxLayout(self)
        lyt.setContentsMargins(8, 6, 8, 6)
        lyt.setSpacing(4)

        # Kategorie-Badge + Priorität (+ KI-Marker + Urgency-Badge)
        top_row = QHBoxLayout()
        if is_ki:
            # KI-Marker: kleines Robot-Symbol; gleicher Style wie Cat-Badge,
            # damit die Karte ruhig wirkt.
            ki_marker = QLabel("KI")
            ki_marker.setToolTip("Automatisch von der Regel-Engine erzeugt")
            ki_marker.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_CAPTION_XS}px; font-weight: bold; "
                f"color: {t.STATUS_INFO}; background: transparent; "
                f"border: 1px solid {t.STATUS_INFO}; border-radius: 3px; "
                f"padding: 1px 4px;"
            )
            top_row.addWidget(ki_marker)
            # Urgency-Badge nur auf KI-Tasks zeigen — manuelle Tasks haben
            # keine vom Klassifikator vergebene Urgency.
            urgency_color = _URGENCY_COLORS.get(task.urgency, t.ACCENT)
            urgency_label = _URGENCY_LABELS.get(task.urgency, task.urgency.upper())
            urgency_badge = QLabel(urgency_label)
            urgency_badge.setToolTip(
                _URGENCY_TOOLTIPS.get(task.urgency, "")
            )
            urgency_badge.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_CAPTION_XS}px; font-weight: bold; "
                f"color: {t.BG_DARK}; background: {urgency_color}; "
                f"border-radius: 3px; padding: 1px 5px; border: none;"
            )
            top_row.addWidget(urgency_badge)
        cat_color = _CATEGORY_COLORS.get(task.category, t.ACCENT)
        cat_badge = QLabel(task.category)
        cat_badge.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_CAPTION_XS}px; color: {theme.get().BG_DARK}; background: {cat_color}; "
            f"border-radius: 3px; padding: 1px 5px; border: none;"
        )
        top_row.addWidget(cat_badge)
        if task.priority == "high":
            prio_lbl = QLabel("[!]")
            prio_lbl.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_CAPTION}px; color: {t.DANGER}; background: transparent; border: none;"
            )
            top_row.addWidget(prio_lbl)
        top_row.addStretch()
        lyt.addLayout(top_row)

        # Titel — Plain-Text erzwingen: Task-Titel enthalten untrusted
        # Software-Namen aus winget/Registry-Scans (R22/-Klasse).
        title_lbl = QLabel(task.title)
        title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold; color: {t.TEXT_MAIN}; "
            f"background: transparent; border: none;"
        )
        lyt.addWidget(title_lbl)

        # Klient
        if task.klient:
            klient_lbl = QLabel(f"Klient: {task.klient}")
            klient_lbl.setTextFormat(Qt.TextFormat.PlainText)
            klient_lbl.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_CAPTION}px; color: {t.TEXT_DIM}; background: transparent; border: none;"
            )
            lyt.addWidget(klient_lbl)

        # Aktionszeile: EINE lesbare Hauptaktion pro Status +
        # "Weitere Aktionen"-Menue. Ersetzt die frueheren Kryptik-Buttons
        # ">"/"OK"/"Bearb."/"X" (24px, Text abgeschnitten, OK doppeldeutig).
        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)

        self._main_btn = QPushButton()
        self._main_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        if task.status == "open":
            self._main_btn.setText("In Arbeit")
            self._main_btn.setToolTip("Aufgabe in Arbeit setzen")
            self._main_btn.clicked.connect(self._on_start)
        elif task.status == "in_progress":
            self._main_btn.setText("Erledigt")
            self._main_btn.setToolTip("Aufgabe als erledigt markieren")
            self._main_btn.clicked.connect(self._on_done)
        else:  # done
            self._main_btn.setText("Wieder öffnen")
            self._main_btn.setToolTip("Aufgabe zurück auf Offen setzen")
            self._main_btn.clicked.connect(self._on_reopen)
        btn_row.addWidget(self._main_btn)
        btn_row.addStretch()

        self._menu = self._build_menu()
        self._menu_btn = QToolButton()
        self._menu_btn.setIcon(get_icon(Icons.MORE_VERT))
        self._menu_btn.setToolTip("Weitere Aktionen")
        self._menu_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._menu_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._menu_btn.setFixedSize(28, 28)
        self._menu_btn.setMenu(self._menu)
        btn_row.addWidget(self._menu_btn)

        lyt.addLayout(btn_row)
        self._style_actions()

        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def _build_menu(self) -> QMenu:
        """Baut das "Weitere Aktionen"-Menü der Karte.

        Enthält die explizite Status-Auswahl (Radio-Gruppe), Bearbeiten,
        Ablehnen, Löschen sowie — nur für KI-Todos — die Feedback-Aktionen
        "Hilfreich"/"Nicht hilfreich" (Audit-only, Sprint S2b).

        Returns:
            Fertig verdrahtetes QMenu (Owner: die Karte).
        """
        t = theme.get()
        menu = QMenu(self)

        # Status-Auswahl: aktueller Status ist markiert + deaktiviert.
        status_group = QActionGroup(menu)
        status_group.setExclusive(True)
        for status, label in (
            ("open", "Offen"),
            ("in_progress", "In Arbeit"),
            ("done", "Erledigt"),
        ):
            act = QAction(label, menu)
            act.setCheckable(True)
            if status == self._task.status:
                act.setChecked(True)
                act.setEnabled(False)
            else:
                act.triggered.connect(
                    lambda _=False, s=status: self._on_set_status(s)
                )
            status_group.addAction(act)
            menu.addAction(act)

        menu.addSeparator()
        act_edit = menu.addAction(get_icon(Icons.EDIT), "Bearbeiten…")
        act_edit.triggered.connect(self._on_edit)
        act_dismiss = menu.addAction(
            get_icon(Icons.BLOCK, color=t.WARNING), "Aufgabe ablehnen…"
        )
        act_dismiss.triggered.connect(self._on_dismiss)

        # Feedback nur fuer KI-Todos (Audit-Trail, kein Status-Effekt).
        if self._task.source == "auto" and self._task.status != "done":
            menu.addSeparator()
            self._act_helpful = menu.addAction(
                get_icon(Icons.THUMB_UP, color=t.SUCCESS), "Hilfreich"
            )
            self._act_helpful.triggered.connect(
                lambda: self._on_feedback(helpful=True)
            )
            self._act_unhelpful = menu.addAction(
                get_icon(Icons.THUMB_DOWN, color=t.TEXT_DIM), "Nicht hilfreich"
            )
            self._act_unhelpful.triggered.connect(
                lambda: self._on_feedback(helpful=False)
            )

        menu.addSeparator()
        # QMenu-Items lassen sich nicht einzeln rot einfaerben — das rote
        # Icon + der Bestaetigungs-Dialog markieren die Destruktivitaet.
        act_delete = menu.addAction(
            get_icon(Icons.DELETE, color=t.DANGER), "Löschen…"
        )
        act_delete.triggered.connect(self._on_delete)
        return menu

    def _style_actions(self) -> None:
        """Setzt die QSS der Aktions-Buttons (initial + Theme-Wechsel)."""
        if self._task.status == "done":
            # Rueckwaerts-Aktion bewusst dezenter als die Vorwaerts-CTAs.
            self._main_btn.setStyleSheet(outline_button_qss())
        else:
            self._main_btn.setStyleSheet(primary_button_qss())
        self._menu_btn.setStyleSheet(card_menu_button_qss())
        self._menu.setStyleSheet(menu_qss())

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        prio_color = _PRIORITY_COLORS.get(self._task.priority, c.ACCENT)
        self.setStyleSheet(
            f"QFrame {{ "
            f"background: {c.CARD_BG}; "
            f"border: 1px solid {c.BORDER}; "
            f"border-left: 3px solid {prio_color}; "
            f"border-radius: 4px; "
            f"margin: 2px; "
            f"}}"
            f"QFrame:hover {{ border-color: {c.ACCENT}; "
            f"border-left-color: {prio_color}; }}"
        )
        self._style_actions()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start_pos = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if not (event.buttons() & Qt.MouseButton.LeftButton):
            return
        if self._drag_start_pos is None:
            return
        delta = event.pos() - self._drag_start_pos
        if delta.manhattanLength() < 10:
            return

        self.setCursor(Qt.CursorShape.ClosedHandCursor)
        drag = QDrag(self)
        mime = QMimeData()
        mime.setData(_TASK_MIME, self._task.id.encode())
        drag.setMimeData(mime)
        drag.setPixmap(self.grab())
        drag.setHotSpot(self._drag_start_pos)
        drag.exec(Qt.DropAction.MoveAction)
        self.setCursor(Qt.CursorShape.OpenHandCursor)

    # ------------------------------------------------------------------
    # Aktions-Handler
    # ------------------------------------------------------------------

    def _on_start(self) -> None:
        try:
            self._svc.move_to_in_progress(self._task.id)
            self._on_refresh()
        except Exception as exc:
            _log.error("Start fehlgeschlagen: %s", exc)

    def _on_done(self) -> None:
        try:
            self._svc.complete_task(self._task.id)
            self._on_refresh()
        except Exception as exc:
            _log.error("Erledigen fehlgeschlagen: %s", exc)

    def _on_reopen(self) -> None:
        try:
            self._svc.reopen_task(self._task.id)
            self._on_refresh()
        except Exception as exc:
            _log.error("Wieder-Oeffnen fehlgeschlagen: %s", exc)

    def _on_set_status(self, status: str) -> None:
        """Setzt den Status aus der Menü-Radio-Gruppe."""
        try:
            if status == "open":
                self._svc.reopen_task(self._task.id)
            elif status == "in_progress":
                self._svc.move_to_in_progress(self._task.id)
            else:  # done
                self._svc.complete_task(self._task.id)
            self._on_refresh()
        except Exception as exc:
            _log.error("Status-Wechsel auf %s fehlgeschlagen: %s", status, exc)

    def _on_edit(self) -> None:
        dlg = TaskFormDialog(self._task, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        if not dlg.task_title:
            return
        # Titel/Beschreibung von KI-Tasks gehören der Reconciliation
        # (Dialog zeigt sie read-only; hier zusätzlich nicht übernehmen).
        if self._task.source != "auto":
            self._task.title = dlg.task_title
            self._task.description = dlg.task_desc
        self._task.category = dlg.task_category
        self._task.klient = dlg.task_klient
        self._task.priority = dlg.task_priority
        try:
            self._svc.update_task(self._task)
            self._on_refresh()
        except Exception as exc:
            _log.error("Bearbeiten fehlgeschlagen: %s", exc)
            # Karte aus der DB neu aufbauen — self._task wurde bereits
            # mutiert und wäre sonst divergent zum persistierten Stand.
            self._on_refresh()

    def _on_dismiss(self) -> None:
        """Lehnt die Aufgabe nach Bestätigung mit Begründung ab."""
        dlg = DismissTaskDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._svc.dismiss_task(self._task.id, reason=dlg.reason)
            self._on_refresh()
        except Exception as exc:
            _log.error("Ablehnen fehlgeschlagen: %s", exc)

    def _on_delete(self) -> None:
        confirm = FinlaiConfirmDialog(
            title="Aufgabe löschen",
            message="Die Aufgabe wird dauerhaft entfernt — auch aus dem "
            "Aufgabenlog. Zum Ausblenden ohne Löschen gibt es "
            "„Aufgabe ablehnen“.",
            confirm_text="Löschen",
            parent=self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._svc.delete_task(self._task.id)
            self._on_refresh()
        except Exception as exc:
            _log.error("Löschen fehlgeschlagen: %s", exc)

    def _on_feedback(self, helpful: bool) -> None:
        """Loggt User-Feedback fuer eine KI-Todo (Sprint S2b).

        Beide Feedback-Buttons werden nach dem Klick deaktiviert, damit
        kein Doppel-Voting moeglich ist. Kein Refresh — die Audit-Wirkung
        ist async und nicht board-relevant.
        """
        try:
            self._svc.record_feedback(self._task.id, helpful=helpful)
        except Exception as exc:  # noqa: BLE001 -- Audit darf UI nicht crashen
            _log.warning("KI-Todo-Feedback fehlgeschlagen: %s", exc)
            return
        # Beide Menü-Aktionen deaktivieren, damit der User sieht: Stimme
        # zaehlt. Bekannte Limitation: Ein Board-Refresh baut die Karten
        # neu — der Disable-Zustand ist Session-lokal (Feedback ist
        # bewusst nicht auf der Task persistiert, vgl. record_feedback).
        if hasattr(self, "_act_helpful"):
            self._act_helpful.setEnabled(False)
        if hasattr(self, "_act_unhelpful"):
            self._act_unhelpful.setEnabled(False)


# ---------------------------------------------------------------------------
# _Column
# ---------------------------------------------------------------------------


class _Column(QWidget):
    """Eine Kanban-Spalte mit Titel und scrollbarer Karten-Liste.

    Akzeptiert Task-Drag-and-Drop und ändert den Status automatisch.
    """

    def __init__(
        self,
        title: str,
        color: str,
        column_status: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._status = column_status
        self._svc: TaskService | None = None
        self._on_refresh = None

        t = theme.get()
        self.setStyleSheet(
            f"background: {t.CARD_BG}; border: 1px solid {t.BORDER}; border-radius: 4px;"
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Spalten-Header
        self._col_header = QWidget()
        self._col_header.setFixedHeight(32)
        self._col_header.setStyleSheet(
            f"background: {t.CARD_BG}; border-bottom: 1px solid {t.BORDER}; "
            f"border-radius: 0;"
        )
        hdr_lyt = QHBoxLayout(self._col_header)
        hdr_lyt.setContentsMargins(10, 4, 10, 4)

        self._title_lbl = QLabel(title)
        self._title_color = color
        self._title_lbl.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold; color: {color}; "
            f"background: transparent; border: none;"
        )
        hdr_lyt.addWidget(self._title_lbl)
        hdr_lyt.addStretch()
        outer.addWidget(self._col_header)

        # Scrollbarer Karten-Bereich
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none; background: transparent;")

        self._cards_widget = _DropTarget()
        self._cards_widget.setStyleSheet("background: transparent;")
        self._cards_widget.setAcceptDrops(True)
        self._cards_widget.task_dropped.connect(self._on_task_dropped)

        self._cards_lyt = QVBoxLayout(self._cards_widget)
        self._cards_lyt.setContentsMargins(4, 4, 4, 4)
        self._cards_lyt.setSpacing(4)
        self._cards_lyt.addStretch()

        scroll.setWidget(self._cards_widget)
        # Viewport muss ebenfalls Drops akzeptieren damit Qt
        # die Events an das innere _DropTarget-Widget weiterleitet
        scroll.setAcceptDrops(True)
        scroll.viewport().setAcceptDrops(True)
        outer.addWidget(scroll)
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(
            f"background: {c.CARD_BG}; border: 1px solid {c.BORDER}; border-radius: 4px;"
        )
        self._col_header.setStyleSheet(
            f"background: {c.CARD_BG}; border-bottom: 1px solid {c.BORDER}; "
            f"border-radius: 0;"
        )
        self._title_lbl.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold; color: {self._title_color}; "
            f"background: transparent; border: none;"
        )

    def set_tasks(self, tasks: list[Task], svc: TaskService, on_refresh) -> None:
        """Setzt die Task-Karten für diese Spalte."""
        self._svc = svc
        self._on_refresh = on_refresh

        # Alte Karten löschen
        while self._cards_lyt.count() > 1:
            item = self._cards_lyt.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        t = theme.get()
        if not tasks:
            lbl = QLabel("Keine Aufgaben")
            lbl.setStyleSheet(
                f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; "
                f"background: transparent; border: none; padding: 8px;"
            )
            self._cards_lyt.insertWidget(0, lbl)
        else:
            for i, task in enumerate(tasks):
                card = _TaskCard(task, svc, on_refresh)
                self._cards_lyt.insertWidget(i, card)

        # Titelzeile mit Anzahl aktualisieren
        base_title = self._title_lbl.text().split(" (")[0]
        self._title_lbl.setText(f"{base_title} ({len(tasks)})")

    def _on_task_dropped(self, task_id: str) -> None:
        """Ändert den Status einer per Drag-and-Drop verschobenen Aufgabe.

        Fix: Vorher refreshte nur der "open"-Zweig das Board — Drops
        auf "In Arbeit"/"Erledigt" speicherten zwar, die Karte sprang aber
        optisch in die alte Spalte zurück. Jetzt refresht JEDER Zweig.
        """
        if not self._svc or not self._on_refresh:
            return
        try:
            task = self._svc.get_task(task_id)
            if not task or task.status == self._status:
                return
            if self._status == "in_progress":
                self._svc.move_to_in_progress(task_id)
            elif self._status == "done":
                self._svc.complete_task(task_id)
            else:  # "open"
                self._svc.reopen_task(task_id)
            self._on_refresh()
        except Exception as exc:
            _log.error("DnD -> %s: %s", self._status, exc)


# ---------------------------------------------------------------------------
# TaskboardWidget
# ---------------------------------------------------------------------------


class TaskboardWidget(QWidget):
    """Kanban-Board mit drei Spalten: Offen, In Arbeit, Erledigt."""

    def __init__(
        self,
        task_service: TaskService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._svc = task_service
        t = theme.get()
        self.setStyleSheet(f"background: {t.CARD_BG};")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(8)

        # Header
        hdr = QHBoxLayout()
        self._board_title = QLabel("Task-Board")
        self._board_title.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: {theme.FONT_SIZE_BODY}px; font-weight: bold; color: {t.ACCENT}; "
            f"background: transparent; border: none;"
        )
        hdr.addWidget(self._board_title)
        hdr.addStretch()

        # Aufgabenlog — Historie erledigter/abgelehnter Aufgaben
        # (die ERLEDIGT-Spalte zeigt bewusst nur den heutigen Tag).
        self._btn_log = QPushButton("Aufgabenlog")
        self._btn_log.setIcon(get_icon(Icons.HISTORY))
        self._btn_log.setFixedHeight(28)
        self._btn_log.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_log.setToolTip(
            "Historie aller erledigten und abgelehnten Aufgaben"
        )
        self._btn_log.setStyleSheet(toolbar_button_qss())
        self._btn_log.clicked.connect(self._on_show_log)
        hdr.addWidget(self._btn_log)

        self._btn_new = QPushButton("Neue Aufgabe")
        self._btn_new.setIcon(get_icon(Icons.ADD))
        self._btn_new.setFixedHeight(28)
        self._btn_new.setStyleSheet(
            f"QPushButton {{ font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; padding: 2px 10px; "
            f"background: {t.BG_BUTTON}; color: {t.TEXT_MAIN}; "
            f"border: 1px solid {t.ACCENT}; border-radius: 4px; }}"
            f"QPushButton:hover {{ border: 2px solid {t.ACCENT}; color: {t.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {t.ACCENT}; color: {t.BG_MAIN}; }}"
        )
        self._btn_new.clicked.connect(self._on_new_task)
        hdr.addWidget(self._btn_new)
        outer.addLayout(hdr)

        self._sep = QFrame()
        self._sep.setFrameShape(QFrame.Shape.HLine)
        self._sep.setFixedHeight(1)
        self._sep.setStyleSheet(f"background: {t.BORDER}; border: none;")
        outer.addWidget(self._sep)

        # Spalten
        cols_row = QHBoxLayout()
        cols_row.setSpacing(8)

        self._col_open = _Column("OFFEN", t.TEXT_MAIN, "open")
        self._col_progress = _Column("IN ARBEIT", t.ACCENT, "in_progress")
        self._col_done = _Column("ERLEDIGT", t.SUCCESS, "done")

        cols_row.addWidget(self._col_open)
        cols_row.addWidget(self._col_progress)
        cols_row.addWidget(self._col_done)
        outer.addLayout(cols_row)

        self._refresh()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(f"background: {c.CARD_BG};")
        self._board_title.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: {theme.FONT_SIZE_BODY}px; font-weight: bold; color: {c.ACCENT}; "
            f"background: transparent; border: none;"
        )
        self._btn_new.setStyleSheet(
            f"QPushButton {{ font-size: {theme.FONT_SIZE_CAPTION}px; padding: 2px 10px; "
            f"background: {c.BG_BUTTON}; color: {c.TEXT_MAIN}; "
            f"border: 1px solid {c.ACCENT}; border-radius: 3px; }}"
            f"QPushButton:hover {{ border: 2px solid {c.ACCENT}; color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT}; color: {c.BG_MAIN}; }}"
        )
        self._btn_log.setStyleSheet(toolbar_button_qss())
        self._sep.setStyleSheet(f"background: {c.BORDER}; border: none;")

    def _refresh(self) -> None:
        """Lädt Tasks neu und aktualisiert alle Spalten."""
        try:
            board = self._svc.get_board_data()
            self._col_open.set_tasks(board["open"], self._svc, self._refresh)
            self._col_progress.set_tasks(board["in_progress"], self._svc, self._refresh)
            self._col_done.set_tasks(board["done_today"], self._svc, self._refresh)
        except Exception as exc:
            _log.error("Board-Refresh fehlgeschlagen: %s", exc)

    def _on_show_log(self) -> None:
        """Öffnet den Aufgabenlog-Dialog."""
        from tools.mainpage.gui.task_log_dialog import (  # noqa: PLC0415
            TaskLogDialog,
        )

        TaskLogDialog(self._svc, self).exec()

    def _on_new_task(self) -> None:
        """Öffnet Dialog für neue Aufgabe."""
        dlg = TaskFormDialog(parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        title = dlg.task_title
        if not title:
            return
        try:
            self._svc.create_task(
                title=title,
                description=dlg.task_desc,
                category=dlg.task_category,
                klient=dlg.task_klient,
                priority=dlg.task_priority,
            )
            self._refresh()
        except Exception as exc:
            _log.error("Task konnte nicht erstellt werden: %s", exc)
