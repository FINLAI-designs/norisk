"""
quickstart_widget — Schnellstart-Widget des Mainpage-Dashboards.

Zeigt Buttons für die zuletzt genutzten Tools.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget

from core import theme

# App-spezifische Fallback-Tools wenn Verlauf leer ist
_DEFAULT_TOOLS_BY_APP: dict[str, list[tuple[str, str]]] = {
    "finlai": [
        ("buchprüfung", ""),
        ("teachings", ""),
        ("finanzprüfung", ""),
        ("xml_reader", ""),
        ("KI-Integration", ""),
    ],
    "norisk": [
        ("cyber_dashboard", ""),
        ("api_security", ""),
        ("network_scanner", ""),
        ("dependency_auditor", ""),
        ("cert_monitor", ""),
    ],
    "automate": [
        ("maps", ""),
        ("migrationscheck", ""),
        ("xml_reader", ""),
        ("robotic", ""),
        ("KI-Integration", ""),
    ],
}

# Tool-Name → Nav-Schlüssel für Sidebar-Navigation
_TOOL_TO_NAV: dict[str, str] = {
    "maps": "maps:import",
    "buchprüfung": "buchprüfung",
    "finanzprüfung": "finanzprüfung",
    "teachings": "teachings",
    "ocr_benchmark": "ocr_benchmark",
    "OCR Benchmark": "ocr_benchmark",
    "xml_reader": "xml_reader:camt",
    "migrationscheck": "migrationscheck",
    "Migrationscheck": "migrationscheck",
    "robotic": "robotic:dashboard",
    "Robotic": "robotic:dashboard",
    "ki_integration": "ki:ollama",
    "KI-Integration": "ki:ollama",
    "cyber_dashboard": "cyber_dashboard",
    "api_security": "api_security",
    "network_scanner": "network_scanner",
    "dependency_auditor": "dependency_auditor",
    "cert_monitor": "cert_monitor",
}


class _ToolButton(QFrame):
    """Klickbarer Schnellstart-Button für ein Tool.

    Signals:
        clicked(str): Navigationsschlüssel des gewählten Tools.
    """

    clicked = Signal(str)

    def __init__(
        self,
        label: str,
        icon: str,
        nav_key: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        t = theme.get()
        self._nav_key = nav_key
        self.setFixedHeight(36)
        self.setCursor(self.cursor())
        self.setStyleSheet(
            f"QFrame {{ background: {t.BG_BUTTON}; border: 1px solid {t.BORDER}; "
            f"border-radius: 4px; }} "
            f"QFrame:hover {{ background: {t.ACCENT}; border-color: {t.ACCENT}; }}"
        )

        lyt = QHBoxLayout(self)
        lyt.setContentsMargins(8, 4, 8, 4)
        lyt.setSpacing(6)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(
            "font-size: 14px; background: transparent; border: none;"
        )
        lyt.addWidget(icon_lbl)

        self._name_lbl = QLabel(label)
        self._name_lbl.setStyleSheet(
            f"font-size: 12px; color: {t.TEXT_MAIN}; background: transparent; border: none;"
        )
        lyt.addWidget(self._name_lbl)
        lyt.addStretch()
        # KEIN eigener theme-Listener: die Buttons werden alle 60s neu
        # erzeugt — pro Instanz registrierte Listener würden in
        # theme._listeners unbegrenzt anwachsen (Review-P2-3). Das
        # Eltern-Widget styled seine Buttons in apply_theme durch.

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(
            f"QFrame {{ background: {c.BG_BUTTON}; border: 1px solid {c.BORDER}; "
            f"border-radius: 4px; }} "
            f"QFrame:hover {{ background: {c.ACCENT}; border-color: {c.ACCENT}; }}"
        )
        self._name_lbl.setStyleSheet(
            f"font-size: 12px; color: {c.TEXT_MAIN}; background: transparent; border: none;"
        )

    def mousePressEvent(self, event) -> None:
        """Emittiert clicked-Signal bei Mausklick."""
        self.clicked.emit(self._nav_key)
        super().mousePressEvent(event)


class QuickstartWidget(QWidget):
    """Schnellstart-Panel mit den zuletzt genutzten Tools.

    Signals:
        tool_requested(str): Nav-Schlüssel des gewählten Tools.
    """

    tool_requested = Signal(str)

    def __init__(
        self,
        service,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Schnellstart-Widget.

        Args:
            service: QuickstartService-Instanz fuer Verlauf-Abfrage
: GUI nutzt application/-Service statt
                Repository-Direktimport).
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._service = service
        t = theme.get()
        # AP3 (Option A): kompakte einzeilige Leiste in der Header-
        # Zone oben rechts — optisch Teil des Begrüßungs-Bands
        # (gleicher Hintergrund + gleiche Unterkante wie HeaderWidget).
        self.setStyleSheet(
            f"background-color: {t.CARD_BG}; border-bottom: 1px solid {t.ACCENT};"
        )
        self.setFixedHeight(80)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(12, 8, 20, 8)
        outer.setSpacing(8)

        self._header_lbl = QLabel("Schnellstart")
        self._header_lbl.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 12px; font-weight: bold; color: {t.TEXT_DIM}; "
            f"background: transparent; border: none;"
        )
        outer.addWidget(self._header_lbl)

        self._btn_area = QHBoxLayout()
        self._btn_area.setSpacing(6)
        outer.addLayout(self._btn_area)

        self._load_tools()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(
            f"background-color: {c.CARD_BG}; border-bottom: 1px solid {c.ACCENT};"
        )
        self._header_lbl.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 12px; font-weight: bold; color: {c.TEXT_DIM}; "
            f"background: transparent; border: none;"
        )
        # Kind-Buttons durchstylen (Buttons registrieren bewusst keinen
        # eigenen Listener, s. _ToolButton.__init__)
        for i in range(self._btn_area.count()):
            item = self._btn_area.itemAt(i)
            widget = item.widget() if item else None
            if isinstance(widget, _ToolButton):
                widget.apply_theme()

    def _load_tools(self) -> None:
        """Lädt zuletzt genutzte Tools und baut Buttons auf (App-gefiltert)."""
        from apps.app_config import get_active_config  # noqa: PLC0415

        cfg = get_active_config()
        app_id = cfg.app_id if cfg else "finlai"
        defaults = _DEFAULT_TOOLS_BY_APP.get(app_id, _DEFAULT_TOOLS_BY_APP["finlai"])

        # Alte Buttons entfernen
        while self._btn_area.count():
            item = self._btn_area.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        recent = self._service.load_recent_tools(limit=5, app_id=app_id)

        # Buttons aus Verlauf
        shown = 0
        for tool_name in recent:
            nav_key = _TOOL_TO_NAV.get(tool_name, tool_name.lower())
            icon = ""
            btn = _ToolButton(tool_name, icon, nav_key)
            btn.clicked.connect(self.tool_requested)
            self._btn_area.addWidget(btn)
            shown += 1

        # Fallback-Buttons wenn Verlauf leer/kurz
        for name, icon in defaults[shown:5]:
            nav_key = _TOOL_TO_NAV.get(name, name.lower())
            btn = _ToolButton(name, icon, nav_key)
            btn.clicked.connect(self.tool_requested)
            self._btn_area.addWidget(btn)

        self._btn_area.addStretch()

    def refresh(self) -> None:
        """Aktualisiert die Schnellstart-Buttons."""
        self._load_tools()
