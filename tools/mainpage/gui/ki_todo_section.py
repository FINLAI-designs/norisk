"""ki_todo_section — "FINLAI empfiehlt"-Section für die Mainpage (Sprint S2b).

Bis hieß die Sektion "Was tun?" — mit dem Maskottchen-Branding
spricht FINLAI hier jetzt selbst.

Anzeige der Top-3 KI-Todos (Tasks mit ``source == "auto"``)
auf der Mainpage. Lädt direkt über:class:`TaskService` aus der
gemeinsamen ``tasks``-DB — keine separate Persistenzschicht.

Sortier-Reihenfolge:
  1. ``urgency`` absteigend (quick > mittel > langfrist)
  2. ``created_at`` absteigend (neuste zuerst bei Gleichstand)
  3. ``status != "done"`` (erledigte Tasks sind irrelevant)

States:
  - **Empty**: keine offenen KI-Todos → Hinweis-Block mit Erklärtext.
  - **Populated**: bis zu 3 Hero-Karten nebeneinander.
  - **Loading / Cancel**: bewusst kein Loading-State in S2b — der
    Refresh ist synchron (DB-Read, < 50 ms). Das briefing_service-
    Pattern (LLM-Cancel) wird in Iteration 2 nachgezogen.

Schichtzugehörigkeit: gui/ — keine Domain-/Application-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.branding import robot_pixmap
from core.icons import Icons, get_icon
from core.logger import get_logger
from tools.mainpage.application.evergreen_provider import (
    EvergreenGatingContext,
    get_evergreens,
)
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.domain.models import Task

_log = get_logger(__name__)

# Sortier-Reihenfolge der Urgency-Klassen — quick zuerst.
_URGENCY_ORDER: dict[str, int] = {
    "quick": 0,
    "mittel": 1,
    "langfrist": 2,
}

# Wiederverwendet aus taskboard_widget — bewusst dupliziert hier statt
# import, damit ki_todo_section ein eigenstaendiges Modul ohne
# Querverbindung zur Kanban-Implementierung bleibt.
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

_MAX_HERO_CARDS = 3


class KiTodoSection(QWidget):
    """Hero-Section mit den drei dringlichsten KI-Todos.

    Args:
        task_service: Geteilter:class:`TaskService` (gleiche Instanz wie
            das Kanban-Board), damit Feedback und Status-Aenderungen sofort
            in beiden Sichten sichtbar werden.
    """

    def __init__(
        self,
        task_service: TaskService,
        parent: QWidget | None = None,
        *,
        defer_initial_refresh: bool = False,
    ) -> None:
        """Initialisiert die Section.

        Args:
            task_service: Geteilter TaskService.
            parent: Eltern-Widget.
            defer_initial_refresh: Wenn ``True``, wird der erste ``refresh``
                (DB-Query Top-3 + Karten-Render, ~46 ms) per ``QTimer(0)`` auf
                NACH dem ersten Paint verschoben (Perf, Cockpit-Startup). Die
                Sektion ist sofort sichtbar (Header/Layout), die Karten erscheinen
                einen Event-Loop-Tick spaeter. Default ``False`` = synchron
                (Tests + Stand-alone-Nutzung bleiben unveraendert).
        """
        super().__init__(parent)
        self._svc = task_service
        self._cards: list[QWidget] = []
        self._build_layout()
        if defer_initial_refresh:
            QTimer.singleShot(0, self.refresh)
        else:
            self.refresh()
        theme.register_listener(self._apply_theme)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Lädt die Tasks neu und rendert die Section."""
        try:
            top = self._top_ki_todos()
        except Exception as exc:  # noqa: BLE001 -- Refresh darf nie crashen
            _log.warning("KiTodoSection-Refresh fehlgeschlagen: %s", exc)
            return
        self._render(top)

    def _open_anleitung(self, task: Task) -> None:
        """Oeffnet die kuratierte Anleitung zu einem KI-Todo (c2).

        Klick statt Hover (bewusste Generierung); der Dialog zeigt den Befund +
        passende Leitfaden-PDFs + Assistent-Hinweis + KI-Disclaimer. Lazy-Import
        + fail-soft, damit ein Dialog-Fehler die Sektion nie crasht.
        """
        try:
            from tools.mainpage.gui.ki_todo_anleitung_dialog import (  # noqa: PLC0415
                KiTodoAnleitungDialog,
            )

            KiTodoAnleitungDialog(task, self).exec()
        except Exception as exc:  # noqa: BLE001 -- ein Dialog darf nie crashen
            _log.warning(
                "KI-Todo-Anleitung nicht verfuegbar: %s", type(exc).__name__
            )

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        t = theme.get()
        self.setStyleSheet(f"background: {t.CARD_BG};")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(6)

        # Header-Zeile: Roboter + Titel + Refresh-Button.
        header_row = QHBoxLayout()
        robot = robot_pixmap(24)
        if not robot.isNull():
            lbl_robot = QLabel()
            lbl_robot.setFixedSize(24, 24)
            lbl_robot.setPixmap(robot)
            lbl_robot.setStyleSheet("background: transparent; border: none;")
            header_row.addWidget(lbl_robot)
        self._title_lbl = QLabel("FINLAI empfiehlt")
        self._title_lbl.setStyleSheet(self._title_css(t))
        header_row.addWidget(self._title_lbl)
        header_row.addStretch()

        self._btn_refresh = QPushButton("Aktualisieren")
        self._btn_refresh.setIcon(get_icon(Icons.REFRESH))
        self._btn_refresh.setFixedHeight(24)
        self._btn_refresh.setStyleSheet(self._refresh_btn_css(t))
        self._btn_refresh.clicked.connect(self.refresh)
        header_row.addWidget(self._btn_refresh)
        outer.addLayout(header_row)

        # Content-Container: wird von ``_render`` neu befüllt.
        self._content_row = QHBoxLayout()
        self._content_row.setSpacing(8)
        outer.addLayout(self._content_row)

    def _apply_theme(self) -> None:
        """Theme-Listener — aktualisiert nur Farben, nicht das Layout."""
        t = theme.get()
        self.setStyleSheet(f"background: {t.CARD_BG};")
        self._title_lbl.setStyleSheet(self._title_css(t))
        self._btn_refresh.setStyleSheet(self._refresh_btn_css(t))

    @staticmethod
    def _title_css(t) -> str:  # noqa: ANN001 -- ThemeColors ist intern
        return (
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: {theme.FONT_SIZE_BODY_LG}px; font-weight: bold; color: {t.ACCENT}; "
            f"background: transparent; border: none;"
        )

    @staticmethod
    def _refresh_btn_css(t) -> str:  # noqa: ANN001 -- ThemeColors ist intern
        return (
            f"QPushButton {{ font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY_SM}px; "
            f"padding: 2px 10px; background: {t.BG_BUTTON}; "
            f"color: {t.TEXT_MAIN}; border: 1px solid {t.BORDER}; "
            f"border-radius: 4px; }}"
            f"QPushButton:hover {{ border-color: {t.ACCENT}; "
            f"color: {t.ACCENT}; }}"
        )

    # ------------------------------------------------------------------
    # Daten
    # ------------------------------------------------------------------

    def _top_ki_todos(self) -> list[Task]:
        """Liefert bis zu 3 KI-Todos: echte Regel-Engine-Tasks zuerst,
        dann Evergreens als Fallback wenn weniger als 3 echte
        Tasks vorhanden sind.

        Evergreens werden via:class:`EvergreenGatingContext`
        gefiltert — "Vollscan starten" haengt nicht mehr in der UI
        wenn der User gerade einen Vollscan beendet hat.

        Läuft über ``get_board_data`` statt über die private
        Repo-API — das frühere Referenz-Pattern (``_TaskCard._on_delete``)
        wurde als Schichtverletzung entfernt.
        """
        board = self._svc.get_board_data()
        candidates: list[Task] = [
            t
            for col in ("open", "in_progress")
            for t in board[col]
            if t.source == "auto"
        ]
        candidates.sort(key=_sort_key, reverse=False)
        acute = candidates[:_MAX_HERO_CARDS]
        # Mit Evergreens auffuellen damit die "FINLAI empfiehlt"-Section nie
        # leer wirkt. Gating-Context steuert welche Templates
        # sinnvoll sind.
        gap = _MAX_HERO_CARDS - len(acute)
        if gap > 0:
            ctx = self._build_evergreen_context()
            acute.extend(get_evergreens(limit=gap, ctx=ctx))
        return acute

    def _build_evergreen_context(self) -> EvergreenGatingContext:
        """Sammelt den State-Snapshot fuer Evergreen-Predicates.

        Delegiert an:func:`build_evergreen_context` in der
        application/-Schicht — der GUI-Layer darf laut Hexagonal-
        Contract nicht direkt auf ``data/`` zugreifen.
        """
        from tools.mainpage.application.evergreen_context_builder import (  # noqa: PLC0415
            build_evergreen_context,
        )

        try:
            return build_evergreen_context()
        except Exception as exc:  # noqa: BLE001 — Context-Build darf nie crashen
            _log.warning(
                "EvergreenContext-Build fehlgeschlagen: %s — leerer Context.",
                type(exc).__name__,
            )
            return EvergreenGatingContext()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(self, tasks: list[Task]) -> None:
        # Bestehende Karten + Empty-State entfernen. ``deleteLater`` ist
        # asynchron — wir setzen zusätzlich ``setParent(None)``, damit
        # ``findChildren`` und ``layout`` das Widget sofort vergessen.
        while self._content_row.count():
            item = self._content_row.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self._cards.clear()

        if not tasks:
            self._content_row.addWidget(_EmptyState(self))
            return
        for task in tasks:
            card = _HeroCard(task, self)
            card.clicked.connect(self._open_anleitung)
            self._content_row.addWidget(card, 1)
            self._cards.append(card)
        # Kleinere Karten-Reihen sollen am rechten Rand atmen statt
        # gestreckt zu werden.
        if len(tasks) < _MAX_HERO_CARDS:
            self._content_row.addStretch()


def _sort_key(task: Task) -> tuple[int, str]:
    """Sortier-Helper: erst Urgency-Index, dann ``created_at`` invertiert."""
    urgency_idx = _URGENCY_ORDER.get(task.urgency, len(_URGENCY_ORDER))
    # ``created_at`` als ISO-String — wir wollen neuste zuerst, also
    # invertieren wir die String-Ordnung lexikographisch.
    inverted_created = "".join(
        chr(0x10FFFF - ord(c)) if ord(c) < 0x10FFFF else c
        for c in (task.created_at or "")
    )
    return (urgency_idx, inverted_created)


# ---------------------------------------------------------------------------
# _HeroCard — pro Top-3 KI-Todo
# ---------------------------------------------------------------------------


class _HeroCard(QFrame):
    """Eine prominente Karte für einen KI-Todo in der Hero-Section.

    Bewusst breiter als ``_TaskCard`` aus dem Kanban: Headline + Action-
    Snippet sichtbar ohne Klick. Klick auf die Karte oeffnet die kuratierte
    Anleitung (c2): ``clicked(Task)`` -> ``KiTodoSection`` zeigt einen Dialog
    mit Befund + passenden Leitfaden-PDFs + Assistent-Hinweis + KI-Disclaimer.

    Signals:
        clicked(object): Der:class:`Task` dieser Karte (beim Linksklick).
    """

    clicked = Signal(object)

    def __init__(self, task: Task, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._task = task
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        t = theme.get()
        urgency_color = _URGENCY_COLORS.get(task.urgency, t.ACCENT)
        self.setStyleSheet(
            f"QFrame {{ background: {t.BG_INPUT}; "
            f"border: 1px solid {t.BORDER}; "
            f"border-left: 4px solid {urgency_color}; "
            f"border-radius: 4px; padding: 6px; }}"
        )

        lyt = QVBoxLayout(self)
        lyt.setContentsMargins(8, 8, 8, 8)
        lyt.setSpacing(4)

        # Top-Zeile: Urgency-Badge + Source-Tool.
        top_row = QHBoxLayout()
        urgency_badge = QLabel(_URGENCY_LABELS.get(task.urgency, task.urgency.upper()))
        urgency_badge.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_CAPTION_XS}px; font-weight: bold; "
            f"color: {t.BG_DARK}; background: {urgency_color}; "
            f"border-radius: 3px; padding: 1px 6px; border: none;"
        )
        top_row.addWidget(urgency_badge)
        if task.source_tool:
            tool_lbl = QLabel(task.source_tool)
            tool_lbl.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_CAPTION_XS}px; color: {t.TEXT_DIM}; "
                f"background: transparent; border: none;"
            )
            top_row.addWidget(tool_lbl)
        top_row.addStretch()
        lyt.addLayout(top_row)

        # Headline — KI-generierte Titel sind untrusted: nie als
        # Auto-RichText rendern (R22, Boy-Scout aus-Review).
        title_lbl = QLabel(task.title)
        title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold; color: {t.TEXT_MAIN}; "
            f"background: transparent; border: none;"
        )
        lyt.addWidget(title_lbl)

        # Action-Snippet aus der Description (zweiter Absatz).
        action_text = _action_excerpt(task.description)
        if action_text:
            action_lbl = QLabel(action_text)
            action_lbl.setWordWrap(True)
            action_lbl.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_CAPTION}px; color: {t.TEXT_DIM}; "
                f"background: transparent; border: none;"
            )
            lyt.addWidget(action_lbl)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001 — Qt-Override
        """Linksklick auf die Karte oeffnet die kuratierte Anleitung (c2)."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._task)
        super().mousePressEvent(event)


def _action_excerpt(description: str) -> str:
    """Schneidet den Action-Teil aus der Storytelling-Description heraus.

    ``KiTodoService`` schreibt ``description = explanation + "\\n\\n" + action``.
    Im Hero-Card zeigen wir den Action-Teil — das ist der "was tun"-Pfad.
    Fallback bei Tasks ohne klares Format: erste 140 Zeichen.
    """
    if not description:
        return ""
    parts = description.split("\n\n", 1)
    if len(parts) == 2:
        return parts[1].strip()
    return description.strip()[:140]


# ---------------------------------------------------------------------------
# _EmptyState — wenn keine KI-Todos da sind
# ---------------------------------------------------------------------------


class _EmptyState(QFrame):
    """Empty-State-Block für die Hero-Section (AI_TODO 5.6)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        t = theme.get()
        self.setStyleSheet(
            f"QFrame {{ background: {t.BG_INPUT}; "
            f"border: 1px dashed {t.BORDER}; "
            f"border-radius: 4px; padding: 12px; }}"
        )

        lyt = QVBoxLayout(self)
        lyt.setContentsMargins(12, 12, 12, 12)
        lyt.setSpacing(4)

        title = QLabel("Alles ruhig — nichts zu tun")
        title.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold; color: {t.TEXT_MAIN}; "
            f"background: transparent; border: none;"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lyt.addWidget(title)

        body = QLabel(
            "Ich passe weiter auf: Sobald ein Scan etwas findet, melde "
            "ich mich hier mit konkreten naechsten Schritten."
        )
        body.setWordWrap(True)
        body.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_CAPTION}px; color: {t.TEXT_DIM}; "
            f"background: transparent; border: none;"
        )
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lyt.addWidget(body)
