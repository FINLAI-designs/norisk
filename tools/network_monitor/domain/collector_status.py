"""network_monitor.domain.collector_status — Health-Verdikt der Collector-Aufgabe.

Reine Domain-Logik (I/O-frei, ohne Windows/COM testbar): leitet aus den
Roh-Fakten ueber die geplante Windows-Aufgabe (registriert? Action-Ziel
vorhanden? Action startbar?) ein dreiwertiges Health-Verdikt ab.

Hintergrund, ex-): Der fruehere Status war ein blosser Boolean
(„registriert ja/nein"). Er konnte den Fall „Aufgabe registriert, zeigt aber
auf einen geloeschten Worktree-Pfad und laeuft nicht" nicht ausdruecken und
meldete ihn faelschlich als aktiv. Das dreiwertige:class:`CollectorStatus`
schliesst diese Luecke strukturell statt per aufgesetzter Defensive.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

#: Win32-Codes aus ``IRegisteredTask.LastTaskResult``, die bedeuten: die Action
#: konnte gar nicht GESTARTET werden (Datei/Pfad fehlt) -> Aufgabe ist kaputt.
#: Bewusst NUR diese eindeutigen „kann-nicht-starten"-Codes und KEINE generischen
#: Exit-/Termination-Codes: ein regulaer beendeter Dauer-Collector
#: (ExecutionTimeLimit=PT0S) startet beim naechsten Logon neu und ist NICHT kaputt
#: — ihn als BROKEN zu melden waere genau der invertierte False-Positive.
#: Den Original-Bug (toter Worktree-Pfad) traegt ohnehin ``target_exists=False``.
_ERROR_FILE_NOT_FOUND = 0x2
_ERROR_PATH_NOT_FOUND = 0x3
_START_FAILURE_RESULTS = frozenset({_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND})


class CollectorStatus(StrEnum):
    """Health-Zustand der geplanten Collector-Aufgabe.

    Attributes:
        NOT_INSTALLED: Keine geplante Aufgabe registriert.
        ACTIVE: Aufgabe registriert, Action-Ziel vorhanden, letzter Lauf ok.
        BROKEN: Aufgabe registriert, aber Action-Ziel fehlt oder die Action
            konnte nicht starten (Datei/Pfad fehlt) — sie laeuft also nicht
-Konstellation).
    """

    NOT_INSTALLED = "not_installed"
    ACTIVE = "active"
    BROKEN = "broken"


@dataclass(frozen=True)
class CollectorTaskHealth:
    """Roh-Fakten ueber die Collector-Aufgabe, aus denen sich das Verdikt ergibt.

    Die Felder werden in der ``data``-Schicht aus dem Windows-Task-Scheduler (COM)
    befuellt; die Ableitung des Verdikts (:meth:`status`) ist reine, I/O-freie
    Domain-Logik und damit ohne Windows testbar.

    Attributes:
        installed: True, wenn die Aufgabe im Scheduler registriert ist.
        target_exists: True, wenn die ausfuehrbare Datei (und ggf. das
            Collector-Skript) der Action auf der Platte existieren.
        last_task_result: ``LastTaskResult`` der Aufgabe (HRESULT/Win32-Code),
            oder ``None``, wenn nicht lesbar/nicht zutreffend.
    """

    installed: bool
    target_exists: bool = False
    last_task_result: int | None = None

    @property
    def status(self) -> CollectorStatus:
        """Leitet das Health-Verdikt aus den Roh-Fakten ab.

        Returns:
            NOT_INSTALLED, wenn keine Aufgabe registriert ist; BROKEN, wenn die
            Aufgabe registriert ist, aber ihr Action-Ziel fehlt oder ihr letzter
            Lauf an einem „kann-nicht-starten"-Fehler scheiterte (Datei/Pfad
            fehlt); sonst ACTIVE.
        """
        if not self.installed:
            return CollectorStatus.NOT_INSTALLED
        if not self.target_exists:
            return CollectorStatus.BROKEN
        if self.last_task_result in _START_FAILURE_RESULTS:
            return CollectorStatus.BROKEN
        return CollectorStatus.ACTIVE
