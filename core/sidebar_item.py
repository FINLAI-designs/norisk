"""
sidebar_item — Datenklassen für den Sidebar-Menübaum.

Definiert die Struktur der Sidebar-Navigation ohne GUI-Abhängigkeiten.
Diese Dataclasses beschreiben ausschließlich *was* angezeigt wird —
das *Wie* liegt in ``core/sidebar.py``.

Schichtzugehörigkeit: core/ (keine PySide6-Abhängigkeiten).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SidebarItem:
    """Ein einzelner anklickbarer Eintrag in der Sidebar.

    Attributes:
        key: Eindeutiger Navigationsschlüssel (z. B. ``"buchprüfung"``
            für ein registriertes Tool oder ``"finance:dashboard"`` für
            einen Platzhalter).
        label: Anzeigetext des Eintrags.
        icon: Emoji-String oder QIcon (Material Symbol).
        tooltip: Tooltip-Text der im Icon-Modus beim Hovern erscheint.
            Wird ``label`` verwendet wenn leer.
        url: Wenn gesetzt, wird im Browser geöffnet statt der Stack
            gewechselt.
        coming_soon: True → Platzhalter „coming soon" statt echtem Tool.
        tool_name: Name des registrierten Tools dem dieser Eintrag
            zugeordnet ist. Leer bei Platzhaltern und Links.
        indent: Einrückungsebene (0 = keine Einrückung, 1 = 20 px,
            2 = 36 px).
        sub_items: Optionale Untereinträge (für zweistufige Gruppen
            wie den XML-Leser).
    """

    key: str
    label: str
    icon: Any  # str (Emoji) oder QIcon (Material Symbol)
    tooltip: str = ""
    url: str = ""
    coming_soon: bool = False
    tool_name: str = ""
    indent: int = 1
    sub_items: list[SidebarItem] = field(default_factory=list)
    license_feature: str = (
        ""  # Feature-Schlüssel aus core/license_features.py; leer = immer aktiv
    )


@dataclass
class SidebarGroup:
    """Aufklappbare Gruppe in der Sidebar (z. B. Finance, TaxTech).

    Attributes:
        key: Eindeutiger Schlüssel der Gruppe.
        label: Anzeigename.
        icon: Emoji-String oder QIcon (Material Symbol).
        items: Liste der Untermenü-Einträge.
        expanded: True wenn die Gruppe beim Start ausgeklappt ist.
    """

    key: str
    label: str
    icon: Any  # str (Emoji) oder QIcon (Material Symbol)
    items: list[SidebarItem] = field(default_factory=list)
    expanded: bool = False
