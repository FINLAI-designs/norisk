"""
tool_registry — Zentrales Register für alle FinlAi-Tools

Die ToolRegistry verwaltet eine geordnete Liste aller registrierten
BaseTool-Instanzen. Sie wird beim App-Start befüllt und anschließend
dem MainWindow übergeben, das die Tools in der Sidebar und im
QStackedWidget darstellt.

Typical usage:
    from core.tool_registry import ToolRegistry
    from tools.budget_tool import BudgetTool

    registry = ToolRegistry
    registry.register(BudgetTool)
    main_window = MainWindow(registry)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.exceptions import ConfigurationError

if TYPE_CHECKING:
    from .base_tool import BaseTool


class ToolRegistry:
    """
    Verwaltungscontainer für alle registrierten BaseTool-Instanzen.

    Die Reihenfolge der Registrierung entspricht der Anzeigereihenfolge
    in der Sidebar des MainWindows. Ein Tool kann nur durch erneuten
    Aufruf von ``register`` hinzugefügt werden; eine Duplikatprüfung
    findet nicht statt.

    Attributes:
        _tools (list[BaseTool]): Interne, geordnete Liste der registrierten Tools.

    Example:
        registry = ToolRegistry
        registry.register(BudgetTool)
        all_tools = registry.get_all
    """

    def __init__(self) -> None:
        """Initialisiert die leere Tool-Liste."""
        self._tools: list[BaseTool] = []

    def register(self, tool: BaseTool) -> None:
        """Registriert ein Tool am Ende der internen Liste.

        Args:
            tool (BaseTool): Eine vollständig initialisierte Instanz einer
                BaseTool-Unterklasse.
        """
        self._tools.append(tool)

    def register_from_module(self, module_path: str) -> None:
        """Importiert ein Tool-Modul und registriert seine BaseTool-Subklasse.

        Durchsucht das importierte Modul nach einer Klasse, die direkt in
        diesem Modul definiert ist und von BaseTool erbt. Wird genau eine
        solche Klasse gefunden, wird eine Instanz davon registriert.

        Args:
            module_path: Vollständiger Python-Modulpfad, z.B.
                         ``"tools.buchprüfung.tool"``.

        Raises:
            ImportError: Wenn das Modul nicht importiert werden kann.
            ValueError: Wenn keine oder mehrere BaseTool-Subklassen
                          im Modul gefunden werden.
        """
        import importlib
        import inspect

        from core.base_tool import BaseTool  # noqa: PLC0415

        module = importlib.import_module(module_path)
        candidates = [
            obj
            for _, obj in inspect.getmembers(module, inspect.isclass)
            if issubclass(obj, BaseTool)
            and obj is not BaseTool
            and obj.__module__ == module.__name__
        ]
        if not candidates:
            raise ConfigurationError(f"Keine BaseTool-Subklasse in '{module_path}' gefunden.")
        if len(candidates) > 1:
            raise ConfigurationError(
                f"Mehrere BaseTool-Subklassen in '{module_path}' gefunden: "
                f"{[c.__name__ for c in candidates]}"
            )
        self._tools.append(candidates[0]())

    def has_tool(self, name: str) -> bool:
        """Prüft ob ein Tool mit dem gegebenen Namen registriert ist.

        Args:
            name: ``BaseTool.name`` des gesuchten Tools.

        Returns:
            True wenn ein Tool mit diesem Namen registriert ist.
        """
        return any(t.name == name for t in self._tools)

    def get_tool(self, name: str) -> BaseTool:
        """Gibt ein registriertes Tool anhand seines Namens zurück.

        Args:
            name: ``BaseTool.name`` des gesuchten Tools.

        Returns:
            Das erste Tool dessen ``name``-Attribut übereinstimmt.

        Raises:
            KeyError: Wenn kein Tool mit diesem Namen registriert ist.
        """
        for tool in self._tools:
            if tool.name == name:
                return tool
        raise KeyError(f"Kein Tool mit name='{name}' registriert.")

    def get_all(self) -> list[BaseTool]:
        """Gibt eine flache Kopie aller registrierten Tools zurück.

        Returns:
            list[BaseTool]: Liste der Tools in Registrierungsreihenfolge.
                Eine Kopie wird zurückgegeben, damit die interne Liste
                nicht versehentlich verändert werden kann.
        """
        return list(self._tools)
