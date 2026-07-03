"""
help_registry — Zentraler Zugriffspunkt auf alle registrierten HelpContent.

Die Registry ist ein schlankes Klassen-Singleton: beim Import dieses
Moduls werden alle Einträge aus:data:`core.help.help_content.ALL_HELP_CONTENTS`
automatisch registriert. Widgets fragen die Registry per ``nav_key`` ab
und bekommen den passenden:class:`HelpContent` zurück.

Beispiel:

    from core.help.help_registry import HelpRegistry

    help_content = HelpRegistry.get("password_checker")
    if help_content is not None:
        self._help_panel = HelpPanel(help_content)

Nicht-existierende Keys geben ``None`` zurück — das Widget kann dann
graceful die Help-UI weglassen statt zu crashen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.help.help_content import ALL_HELP_CONTENTS, HelpContent


class HelpRegistry:
    """Zentrale Registry für:class:`HelpContent`-Einträge.

    Die Klasse ist bewusst stateful (Class-Level-Storage) und nicht als
    Singleton-Instanz implementiert — das macht den Zugriff syntaktisch
    einfach (``HelpRegistry.get(key)``) und hält Tests leichtgewichtig.
    """

    _registry: dict[str, HelpContent] = {}

    @classmethod
    def register(cls, content: HelpContent) -> None:
        """Registriert einen:class:`HelpContent`-Eintrag.

        Bei gleichem ``nav_key`` wird der vorhandene Eintrag überschrieben —
        nützlich für White-Label-Customizing oder Tests.

        Args:
            content: Zu registrierender Eintrag.
        """
        cls._registry[content.nav_key] = content

    @classmethod
    def get(cls, nav_key: str) -> HelpContent | None:
        """Gibt den Eintrag zu einem Nav-Key zurück.

        Args:
            nav_key: Sidebar-Navigationsschlüssel (z.B. ``"password_checker"``).

        Returns:
:class:`HelpContent` oder ``None`` wenn nicht registriert.
        """
        return cls._registry.get(nav_key)

    @classmethod
    def get_all(cls) -> dict[str, HelpContent]:
        """Gibt eine Kopie aller registrierten Einträge zurück.

        Die Kopie verhindert externe Mutation der Registry.

        Returns:
            Dict ``nav_key`` →:class:`HelpContent`.
        """
        return dict(cls._registry)

    @classmethod
    def clear(cls) -> None:
        """Leert die Registry komplett — primär für Tests gedacht."""
        cls._registry.clear()

    @classmethod
    def count(cls) -> int:
        """Anzahl registrierter Einträge."""
        return len(cls._registry)


# ---------------------------------------------------------------------------
# Bulk-Registrierung
# ---------------------------------------------------------------------------
# Wird explizit aus ``apps/__init__.py:launch_app`` aufgerufen, nicht mehr
# als Modul-Level-Seiteneffekt beim Import (Audit-Befund S2-2: implizite
# Mutation beim Import erschwerte Tests).
def init_registry() -> None:
    """Befüllt die Registry aus:data:`ALL_HELP_CONTENTS`.

    Idempotent: jeder Aufruf leert die Registry und befüllt sie neu mit den
    aktuellen Werten — sicher bei Tests, bei mehrfachem Import oder bei
    Hot-Reload.
    """
    HelpRegistry.clear()
    for content in ALL_HELP_CONTENTS:
        HelpRegistry.register(content)
