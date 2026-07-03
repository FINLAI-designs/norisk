"""
session — Sitzungsverwaltung für FINLAI

Singleton das den aktuell angemeldeten Benutzer hält und
Berechtigungsprüfungen für Tools bereitstellt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.auth.models import User

# Tools, die unabhängig von allowed_tools immer zugänglich sind.
# „Übersicht" ist das Cockpit/Welcome-Dock (die EINE Landing-Seite
# Vision B, ``NoRiskDashboardTool.name``). Ein Nutzer mit eingeschränktem
# ``allowed_tools`` soll nicht vor einer leeren Landing-Seite stehen — daher
# wie „Einstellungen" immer erreichbar. (Drift-Guard: ``_COCKPIT_TOOL_NAME``
# in core/dock_mixin.py muss diesem Namen entsprechen — siehe Test.)
_ALWAYS_ACCESSIBLE = {"Einstellungen", "Übersicht"}


class Session:
    """Singleton-Sitzungsverwaltung für den eingeloggten Benutzer.

    Hält den aktuell angemeldeten Benutzer und stellt
    Berechtigungsprüfungen bereit.

    Beispiel::

        session = Session
        session.login(user)
        if session.can_access_tool("Datenvergleich"):
...
    """

    _instance: Session | None = None
    _initialized: bool = False

    def __new__(cls) -> Session:
        """Stellt sicher, dass nur eine Instanz existiert."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialisiert die Session (wird nur beim ersten Aufruf ausgeführt)."""
        if self._initialized:
            return
        self.__class__._initialized = True
        self.current_user: User | None = None

    # ------------------------------------------------------------------
    def login(self, user: User) -> None:
        """Meldet einen Benutzer an und speichert ihn in der Session.

        Args:
            user: Der erfolgreich authentifizierte Benutzer.
        """
        self.current_user = user

    def logout(self) -> None:
        """Meldet den aktuellen Benutzer ab und leert die Session."""
        self.current_user = None

    def is_logged_in(self) -> bool:
        """Gibt True zurück wenn ein Benutzer angemeldet ist."""
        return self.current_user is not None

    def is_admin(self) -> bool:
        """Gibt True zurück wenn der aktuelle Benutzer Adminrechte hat."""
        return self.current_user is not None and self.current_user.role == "admin"

    def can_access_tool(self, tool_name: str) -> bool:
        """Prüft ob der aktuelle Benutzer Zugriff auf ein Tool hat.

        Gibt True zurück wenn:
        - Das Tool in ``_ALWAYS_ACCESSIBLE`` (z.B. Einstellungen) ist.
        - ``allowed_tools`` des Benutzers leer ist (alle Tools erlaubt).
        - Der Tool-Name in ``allowed_tools`` vorkommt.

        Args:
            tool_name: Name des Tools, wie in ``BaseTool.name`` definiert.

        Returns:
            True wenn Zugriff erlaubt, False sonst.
        """
        if self.current_user is None:
            return False
        if tool_name in _ALWAYS_ACCESSIBLE:
            return True
        if not self.current_user.allowed_tools:
            return True
        return tool_name in self.current_user.allowed_tools
