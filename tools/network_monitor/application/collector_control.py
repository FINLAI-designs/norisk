"""network_monitor.application.collector_control — Steuerung der Collector-Aufgabe.

Duenne Application-Fassade ueber die Task-Scheduler-Operationen in
:mod:`tools.network_monitor.data.collector_task_manager`. Sie erlaubt der GUI
(Einstellungen-Tab) das Abfragen/Entfernen der geplanten Aufgabe, ohne die
data-Schicht direkt zu importieren (hexagonale Schichtregel:
``gui -> application -> data``).

Die *Installation* der Aufgabe laeuft bewusst nicht hierueber, sondern im
elevated CLI-Pfad (:mod:`apps.norisk_app`), da sie Administrator-Rechte
erfordert und in einem separaten Prozess registriert wird.
"""

from __future__ import annotations

from tools.network_monitor.data.collector_task_manager import (
    INSTALL_RESULT_REJECTED,
    clear_install_marker,
    collector_task_needs_migration,
    default_collector_action,
    read_install_marker,
    uninstall_collector_task,
)
from tools.network_monitor.data.collector_task_manager import (
    get_collector_status as _data_collector_status,
)
from tools.network_monitor.domain.collector_status import CollectorStatus


def get_collector_status() -> CollectorStatus:
    """Liefert das Health-Verdikt der Collector-Aufgabe.

    Anders als eine reine Registrierungs-Pruefung unterscheidet das Verdikt
    auch den Zustand BROKEN (Aufgabe registriert, zeigt aber auf ein fehlendes
    Ziel oder lief zuletzt fehl) — so wird kein nicht laufender Collector
    faelschlich als aktiv gemeldet.

    Returns:
        Das:class:`CollectorStatus`-Verdikt (NOT_INSTALLED/ACTIVE/BROKEN).
    """
    return _data_collector_status()


def deactivate_collector() -> bool:
    """Entfernt die Collector-Aufgabe aus dem Task-Scheduler.

    Returns:
        True, wenn die Aufgabe entfernt wurde; False, wenn sie nicht existierte.
    """
    return uninstall_collector_task()


def get_collector_action_path() -> str:
    """Liefert den Exe-/Skript-Pfad, den die Aufgabe startet (Action.Path).

    Reine Anzeige-Information für den Settings-Tab F-C-5): zeigt dem
    Anwender, WO der Collector installiert ist bzw. installiert würde — relevant
    für den Hinweis, nach ``%ProgramFiles%`` zu installieren.

    Returns:
        Der absolute Pfad der ausführbaren Datei (gepackt: ``norisk-collector.exe``;
        Dev: der Python-Interpreter).
    """
    return default_collector_action()[0]


def collector_needs_migration() -> bool:
    """True, wenn die installierte Aufgabe auf ein veraltetes Exe-Ziel zeigt.

    Spiegelt:func:`collector_task_needs_migration`: nach einem Update kann die
    Aufgabe auf einen alten Build-Pfad zeigen und muss elevated neu registriert
    werden. Reiner (nicht-elevierter) Detektor für die Status-Anzeige.
    """
    return collector_task_needs_migration()


def take_install_reject() -> str | None:
    """Liest und VERBRAUCHT eine ausstehende Security-Reject-Meldung der Installation.

    Der elevated Install-Prozess kann das Security-Gate nicht über einen Exit-Code
    an die GUI zurückmelden (``relaunch_elevated`` reicht keinen durch), sondern
    hinterlegt eine Marker-Datei. Diese Funktion liest sie und entfernt sie sofort
    (einmalige Anzeige), damit ein alter Marker nicht erneut auslöst.

    Returns:
        Die benutzerlesbare Begründung, wenn die letzte Installation aus
        Sicherheitsgründen abgelehnt wurde; sonst ``None``.
    """
    marker = read_install_marker()
    if marker is None:
        return None
    clear_install_marker()
    if marker.get("result") == INSTALL_RESULT_REJECTED:
        # Fail-soft gegen korrupte/manipulierte Marker (Same-User-UX-Kanal): nie
        # einen Nicht-String an die GUI (QLabel) reichen — sonst TypeError im Slot.
        reason = marker.get("reason")
        if isinstance(reason, str) and reason:
            return reason
        return "Zielpfad ist benutzer-beschreibbar."
    return None
