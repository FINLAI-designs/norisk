"""
tech_stack.enums — Aufzählungstypen für Tech-Stack-Verwaltung.

Schichtzugehörigkeit: domain/ — keine externen Abhängigkeiten.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from enum import StrEnum


class SystemType(StrEnum):
    """Typ eines System-Profils.

    EIGENES: Das eigene System (genau eines, nicht löschbar).
    KUNDE: Kundensystem (beliebig viele, löschbar).
    """

    EIGENES = "eigenes"
    KUNDE = "kunde"


class ToolStatus(StrEnum):
    """Betriebsstatus eines Sicherheits-Tools.

    AKTIV: Tool ist installiert und aktiv.
    INAKTIV: Tool ist installiert, aber deaktiviert.
    FEHLT: Kein Tool vorhanden.
    UNBEKANNT: Status nicht bekannt.
    """

    AKTIV = "aktiv"
    INAKTIV = "inaktiv"
    FEHLT = "fehlt"
    UNBEKANNT = "unbekannt"
