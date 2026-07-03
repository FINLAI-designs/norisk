"""
base_tool — Abstrakte Basisklasse für alle Tools in FinlAi

Definiert das Interface, dem jedes Tool folgen muss. Jedes Tool
besitzt einen Anzeigenamen, ein Icon und muss ein Widget liefern,
das im Haupt-Stack des MainWindows angezeigt wird.

Typical usage:
    from core.base_tool import BaseTool
    from PySide6.QtWidgets import QWidget, QLabel

    class MyTool(BaseTool):
        name = "Mein Tool"
        icon = "build" # Google-Material-Symbol-Key

        def create_widget(self, parent=None):
            return QLabel("Hallo Welt", parent)

Author: Patrick Riederich
Version: 1.0
"""

from abc import ABC, abstractmethod

from PySide6.QtWidgets import QWidget


class BaseTool(ABC):
    """
    Abstrakte Basisklasse für ein FinlAi-Tool.

    Jedes Tool erbt von dieser Klasse und implementiert ``create_widget``.
    Der ToolRegistry wird eine Instanz der konkreten Klasse übergeben;
    das MainWindow ruft ``create_widget`` auf und zeigt das zurückgegebene
    Widget im zentralen QStackedWidget an.

    Attributes:
        name (str): Anzeigename des Tools, erscheint in der Sidebar.
        icon (str): Google-Material-Symbol-Key (siehe https://fonts.google.com/icons),
            wird ueber ``core.icons.get_icon`` als QIcon gerendert.

    Example:
        class BudgetTool(BaseTool):
            name = "Budget"
            icon = "euro"

            def create_widget(self, parent=None):
                return BudgetWidget(parent)
    """

    name: str = ""
    icon: str = ""
    feature_name: str = ""  # vestigial (Lizenz-Gating mit/ entfernt); nicht mehr ausgewertet

    @abstractmethod
    def create_widget(self, parent: QWidget | None = None) -> QWidget:
        """Erstellt und gibt das Haupt-Widget dieses Tools zurück.

        Args:
            parent (QWidget | None): Optionales Eltern-Widget, das an den
                Konstruktor des zurückgegebenen Widgets weitergegeben wird.

        Returns:
            QWidget: Das vollständig initialisierte Widget des Tools.
        """
        ...
