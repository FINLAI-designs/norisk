"""network_monitor.domain.exceptions — Exception-Hierarchie des Tools (R-Exc).

Basis-Exception ``NetworkMonitorError`` plus abgeleitete Domain-Fehler. Bewusst
**nicht** von:class:`PermissionError` abgeleitet: der GUI-/CLI-Pfad behandelt
``PermissionError`` als „nicht elevated → erneut mit UAC starten". Eine
Pfad-Vertrauens-Ablehnung darf KEINE Re-Elevation auslösen (die hülfe nichts —
der Pfad bliebe benutzer-beschreibbar), daher ein eigener Typ.
"""

from __future__ import annotations


class NetworkMonitorError(Exception):
    """Basis-Exception für das Network-Monitor-Tool."""


class UntrustedCollectorPathError(NetworkMonitorError):
    """Der Collector-Installationspfad ist durch Nicht-Admins manipulierbar (EoP).

    Wird von:func:`tools.network_monitor.data.collector_task_manager.install_collector_task`
    geworfen, wenn das Ziel der HIGHEST-Aufgabe in einem benutzer-beschreibbaren
    Pfad läge — dort könnte ein unprivilegierter Angreifer die Exe/das Skript
    ersetzen und damit Code als elevated ausführen F-C-3, Security-Gate).
    """


class WhitelistEntryError(NetworkMonitorError):
    """Eine Whitelist-Eingabe ist ungültig oder bereits vorhanden F-D-GUI).

    Wird vom:class:`tools.network_monitor.application.whitelist_service.WhitelistService`
    geworfen, wenn ein hinzuzufügendes Token nicht als IP/CIDR parst oder das Netz
    schon in der Whitelist steht. Die GUI fängt den Fehler und zeigt die Meldung
    als Inline-Hinweis am Eingabefeld (keine Re-Elevation, kein Crash).
    """


class ConversationFilterError(NetworkMonitorError):
    """Ein Experten-Filter-Ausdruck ist syntaktisch/semantisch ungültig (Phase 5).

    Wird vom deklarativen Filter-Parser
    (:mod:`tools.network_monitor.application.conversation_filter`) geworfen, wenn ein
    Ausdruck ein unbekanntes Feld, einen unzulässigen Operator oder einen nicht
    passenden Wert enthält. Der Parser wertet NIE ``eval``/``exec`` aus; ungültige
    Eingaben enden hier statt in Code-Ausführung. Die GUI fängt den Fehler und zeigt
    ihn als Inline-Hinweis am Filter-Feld.
    """
