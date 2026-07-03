"""services — Factory fuer das Mainpage-Service-Buendel.

Stellt eine zentrale Stelle bereit, an der die Mainpage-Services
(``JournalService``/``TaskService``/``QuickstartService``) fuer das
Widget gemeinsam mit dem zugrundeliegenden Repository erzeugt werden.
Damit muss die GUI weder ``MainpageRepository`` direkt importieren noch
die Wire-Reihenfolge der Services kennen.

Schichtzugehoerigkeit: ``application/`` (orchestriert nur).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.application.quickstart_service import QuickstartService
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.data.mainpage_repository import MainpageRepository


@dataclass(frozen=True, slots=True)
class MainpageServices:
    """Buendel der Mainpage-Services fuer das Dashboard-Widget.

    ``frozen=True`` weil das Buendel selbst ein Value Object ist —
    die enthaltenen Service-Objekte sind weiterhin stateful, aber die
    Zuordnung Buendel→Services veraendert sich zur Laufzeit nicht.
    """

    journal: JournalService
    tasks: TaskService
    quickstart: QuickstartService


def create_mainpage_services() -> MainpageServices:
    """Baut alle Mainpage-Services mit einem geteilten Repository.

    Returns:
        ``MainpageServices``-Buendel — Journal, Tasks, Quickstart auf
        derselben ``MainpageRepository``-Instanz.
    """
    repo = MainpageRepository()
    journal = JournalService(repo)
    tasks = TaskService(repo, journal)
    quickstart = QuickstartService(repo)
    return MainpageServices(journal=journal, tasks=tasks, quickstart=quickstart)
