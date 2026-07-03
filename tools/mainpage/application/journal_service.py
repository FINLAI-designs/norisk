"""
journal_service — Use-Case-Schicht für das Tagesprotokoll.

Verwaltet Journal-Einträge: manuelle Notizen, erledigte Aufgaben,
Tool-Nutzung und automatische Audit-Log-Übernahmen.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from core.logger import get_logger
from tools.mainpage.data.mainpage_repository import MainpageRepository
from tools.mainpage.domain.models import JournalEntry, Task

logger = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _today_str() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


class JournalService:
    """Verwaltet das Tagesprotokoll.

    Attributes:
        _repo: Datenzugriffsschicht.
    """

    def __init__(self, repo: MainpageRepository) -> None:
        """Initialisiert den Service.

        Args:
            repo: Repository-Instanz (Pflicht — kein Default für klare DI).
        """
        self._repo = repo

    # -----------------------------------------------------------------------
    # Einträge anlegen
    # -----------------------------------------------------------------------

    def add_note(self, title: str, content: str = "") -> JournalEntry:
        """Fügt manuelle Notiz hinzu.

        Args:
            title: Titel der Notiz.
            content: Optionaler Langtext.

        Returns:
            Neu erstellter JournalEntry.
        """
        entry = JournalEntry(
            id=str(uuid.uuid4()),
            date=_today_str(),
            timestamp=_now_iso(),
            entry_type="note",
            title=title,
            content=content,
        )
        self._repo.save_entry(entry)
        logger.debug("Notiz angelegt: %s", entry.id)
        return entry

    def add_task_done(self, task: Task) -> None:
        """Protokolliert erledigte Aufgabe.

        Args:
            task: Erledigte Task-Instanz.
        """
        entry = JournalEntry(
            id=str(uuid.uuid4()),
            date=_today_str(),
            timestamp=_now_iso(),
            entry_type="task_done",
            title=f"\u2705 {task.title}",
            content=task.description,
            tool_name=task.source_tool,
            task_id=task.id,
            metadata={
                "category": task.category,
                "klient": task.klient,
            },
        )
        self._repo.save_entry(entry)
        logger.debug("Task-done protokolliert: %s", task.id)

    def add_task_auto_done(self, task: Task, reason: str) -> None:
        """Protokolliert eine automatisch erledigte Aufgabe.

        Eigener Eintragstyp-Inhalt gegenüber:meth:`add_task_done`, damit
        das Tagesprotokoll Auto-Abschlüsse (Reconciliation) von manuellen
        Erledigungen unterscheiden kann.

        Args:
            task: Automatisch erledigte Task-Instanz.
            reason: Maschinelle Begründung (z. B. "Update installiert").
        """
        entry = JournalEntry(
            id=str(uuid.uuid4()),
            date=_today_str(),
            timestamp=_now_iso(),
            entry_type="auto",
            title=f"Automatisch erledigt: {task.title}",
            content=reason,
            tool_name=task.source_tool,
            task_id=task.id,
            metadata={
                "category": task.category,
                "klient": task.klient,
            },
        )
        self._repo.save_entry(entry)
        logger.debug("Auto-Erledigung protokolliert: %s", task.id)

    def add_tool_used(self, tool_name: str, details: str = "") -> None:
        """Protokolliert Tool-Nutzung.

        Wird automatisch aufgerufen wenn ein Tool eine Aktion abschließt.

        Args:
            tool_name: Name des verwendeten Tools.
            details: Optionale Zusatzinformation.
        """
        entry = JournalEntry(
            id=str(uuid.uuid4()),
            date=_today_str(),
            timestamp=_now_iso(),
            entry_type="tool_used",
            title=f"\U0001f527 {tool_name}",
            content=details,
            tool_name=tool_name,
        )
        self._repo.save_entry(entry)
        self._repo.save_tool_used(tool_name)
        logger.debug("Tool-Nutzung protokolliert: %s", tool_name)

    def add_from_audit_log(
        self,
        action: str,
        tool: str,
        details: str,
    ) -> None:
        """Fügt Audit-Log-Eintrag hinzu.

        Args:
            action: Bezeichnung der Aktion.
            tool: Name des auslösenden Tools.
            details: Weitere Details.
        """
        entry = JournalEntry(
            id=str(uuid.uuid4()),
            date=_today_str(),
            timestamp=_now_iso(),
            entry_type="auto",
            title=action,
            content=details,
            tool_name=tool,
        )
        self._repo.save_entry(entry)
        logger.debug("Audit-Log-Eintrag hinzugefügt: %s", action)

    # -----------------------------------------------------------------------
    # Einträge abrufen
    # -----------------------------------------------------------------------

    def get_today_summary(self) -> dict:
        """Zusammenfassung des Tages.

        Returns:
            Dict mit Schlüsseln ``entries``, ``notes``, ``tasks_done``,
            ``tools_used`` und ``total``.
        """
        entries = self._repo.load_today()
        return {
            "entries": entries,
            "notes": [e for e in entries if e.entry_type == "note"],
            "tasks_done": [e for e in entries if e.entry_type == "task_done"],
            "tools_used": [e for e in entries if e.entry_type == "tool_used"],
            "total": len(entries),
        }

    def get_today(self) -> list[JournalEntry]:
        """Gibt alle Journal-Einträge des heutigen Tages zurück."""
        return self._repo.load_today()

    def get_by_date(self, date: str) -> list[JournalEntry]:
        """Gibt alle Journal-Einträge eines bestimmten Datums zurück.

        Args:
            date: Datum im Format ``"YYYY-MM-DD"``.
        """
        return self._repo.load_by_date(date)

    def get_recent(self, limit: int = 20) -> list[JournalEntry]:
        """Gibt die neuesten Journal-Einträge zurück.

        Args:
            limit: Maximale Anzahl zurückzugebender Einträge.
        """
        return self._repo.load_recent(limit=limit)

    def get_recent_tools(self, limit: int = 5) -> list[str]:
        """Gibt die zuletzt genutzten Tool-Namen zurück (dedupliziert).

        Args:
            limit: Maximale Anzahl zurückzugebender Tools.
        """
        return self._repo.load_recent_tools(limit=limit)
