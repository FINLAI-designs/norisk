"""
tool — Tool-Registrierung des Mainpage-Dashboards für FINLAI.

Registriert das Dashboard unter dem Namen "Home" bei der ToolRegistry
und ersetzt damit das bisherige WelcomeTool als Standard-Startseite.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from core.base_tool import BaseTool


class MainpageTool(BaseTool):
    """FinlAi-Tool-Implementierung für das Mainpage-Dashboard.

    Zeigt eine personalisierte Startseite mit Task-Board,
    Tagesprotokoll, Schnellstart und Aktivitäts-Übersicht.

    Attributes:
        name: Anzeigename — "Home" (ersetzt WelcomeTool).
        icon: Emoji-Icon für den Seitenleisten-Eintrag.
    """

    name = "Home"
    icon = "home"

    def create_widget(self, parent: QWidget | None = None) -> QWidget:
        """Erstellt und gibt das Dashboard-Widget zurück.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            MainpageWidget-Instanz.
        """
        from tools.mainpage.gui.mainpage_widget import MainpageWidget

        widget = MainpageWidget(parent)
        widget.tool_requested.connect(self._on_tool_requested)
        return widget

    def _on_tool_requested(self, nav_key: str) -> None:
        """Navigiert zum angeforderten Tool via MainWindow.

 AP3: Ein ``#section``-Suffix (z.B. ``"norisk:dashboard#kanban"``)
        wird als ``section``-kwarg an ``navigate_to`` durchgereicht — das
        Ziel-Widget kann darüber per ``apply_navigation`` eine Sektion
        aufklappen. Das Signal selbst bleibt str-only.

        Args:
            nav_key: Navigationsschlüssel des Ziel-Tools, optional mit
                ``#section``-Suffix.
        """
        from PySide6.QtWidgets import QApplication

        key, _, section = nav_key.partition("#")
        kwargs: dict[str, object] = {"section": section} if section else {}

        # Public Navigation-API von MainWindow nutzen (Sprint 3) statt
        # Private-Member-Zugriff via hasattr — behebt Audit-Befund S2-5.
        # `hasattr(window, "navigate_to")` als Type-Guard reicht, weil ein
        # direkter MainWindow-Import hier zirkulär wäre (mainpage wird von
        # MainWindow geladen).
        for window in QApplication.topLevelWidgets():
            if hasattr(window, "navigate_to"):
                window.navigate_to(key, **kwargs)
                return
