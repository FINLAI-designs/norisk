"""
task_service — Use-Case-Schicht für das Task-Board.

Verwaltung des Task-Boards: Erstellen, Status-Übergänge,
automatische Protokollierung und Board-Daten-Aggregation.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from core.audit_log import AuditLogger
from core.logger import get_logger
from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.data.mainpage_repository import MainpageRepository
from tools.mainpage.domain.models import Task

logger = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class TaskService:
    """Verwaltung des Task-Boards.

    Attributes:
        _repo: Datenzugriffsschicht.
        _journal: Journal-Service für automatische Protokolleinträge.
    """

    def __init__(
        self,
        repo: MainpageRepository,
        journal: JournalService,
    ) -> None:
        """Initialisiert den Service.

        Args:
            repo: Repository-Instanz.
            journal: JournalService für automatische Protokolleinträge.
        """
        self._repo = repo
        self._journal = journal

    # -----------------------------------------------------------------------
    # Task-Operationen
    # -----------------------------------------------------------------------

    def create_task(
        self,
        title: str,
        description: str = "",
        category: str = "allgemein",
        klient: str = "",
        priority: str = "normal",
        source: str = "manual",
        source_tool: str = "",
        urgency: str = "mittel",
        evidence_refs: list[dict] | None = None,
        dedup_key: str = "",
    ) -> Task:
        """Erstellt neue Aufgabe.

        Args:
            title: Kurztitel der Aufgabe.
            description: Optionale Beschreibung.
            category: Kategorie (``"tool"``, ``"klient"``, ``"allgemein"``).
            klient: Klientenname.
            priority: Priorität (``"low"``, ``"normal"``, ``"high"``).
            source: Herkunft (``"manual"`` oder ``"auto"``).
            source_tool: Name des aufrufenden Tools.
            urgency: Effort-Klassifikation (``"quick"``/``"mittel"``/
                ``"langfrist"``) — kommt aus der Regel-Engine. Default
                ``"mittel"`` wenn kein Klassifikator-Lauf vorausgegangen ist.
            evidence_refs: Liste von ``{"tool": str, "finding_id": str}``
                Referenzen — füllt:pyattr:`Task.evidence_refs` für
                Drill-Down zur Quelle. ``None`` → leer.
            dedup_key: Stabile Hash-Referenz aus ``tool + finding_type +
                finding_id``. Pflicht für KI-Todos, leer für manuelle Tasks.

        Returns:
            Neu erstellte Task-Instanz.
        """
        now = _now_iso()
        task = Task(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            status="open",
            category=category,
            source=source,
            source_tool=source_tool,
            klient=klient,
            priority=priority,
            created_at=now,
            updated_at=now,
            urgency=urgency,
            evidence_refs=list(evidence_refs) if evidence_refs else [],
            dedup_key=dedup_key,
        )
        self._repo.save_task(task)
        logger.debug("Task erstellt: %s", task.id)
        return task

    def get_task(self, task_id: str) -> Task | None:
        """Gibt eine Aufgabe anhand ihrer ID zurück.

        Args:
            task_id: UUID der gesuchten Aufgabe.

        Returns:
            Task oder None wenn nicht gefunden.
        """
        return self._repo.load_task(task_id)

    def move_to_in_progress(self, task_id: str) -> None:
        """Setzt Task auf In Arbeit.

        Läuft über Load→Save statt ``repo.update_status``, damit
        ``done_at`` beim Rückweg done→in_progress geleert wird (vorher
        blieb der Stempel stehen).

        Args:
            task_id: UUID der Aufgabe.
        """
        task = self._repo.load_task(task_id)
        if not task:
            return
        task.status = "in_progress"
        task.done_at = ""
        task.dismissed_reason = ""
        task.done_note = ""
        task.updated_at = _now_iso()
        self._repo.save_task(task)
        logger.debug("Task in Bearbeitung: %s", task_id)

    def complete_task(self, task_id: str) -> None:
        """Erledigt Task und schreibt automatisch Protokoll-Eintrag.

        Args:
            task_id: UUID der Aufgabe.
        """
        task = self._repo.load_task(task_id)
        if not task:
            return

        now = _now_iso()
        task.status = "done"
        task.done_at = now
        task.dismissed_reason = ""
        # Manuelle Erledigung — eine evtl. stale Auto-Notiz (z. B.
        # nach reopen) würde im Aufgabenlog sonst falsch als
        # "Automatisch erledigt" angezeigt.
        task.done_note = ""
        task.updated_at = now
        self._repo.save_task(task)

        self._journal.add_task_done(task)
        logger.debug("Task abgeschlossen: %s", task_id)

    def reopen_task(self, task_id: str) -> None:
        """Setzt eine erledigte oder abgelehnte Task zurück auf Offen.

        Leert ``done_at`` und ``dismissed_reason`` — die Task verhält
        sich danach wie eine frische offene Aufgabe.

        Args:
            task_id: UUID der Aufgabe.
        """
        task = self._repo.load_task(task_id)
        if not task:
            return
        task.status = "open"
        task.done_at = ""
        task.dismissed_reason = ""
        task.done_note = ""
        task.updated_at = _now_iso()
        self._repo.save_task(task)
        logger.debug("Task wieder geoeffnet: %s", task_id)

    def dismiss_task(self, task_id: str, reason: str = "") -> None:
        """Lehnt eine Aufgabe ab (Status ``dismissed``).

        Die Task verschwindet vom Board, bleibt aber in der DB: der
        ``dedup_key`` verhindert weiterhin, dass dieselbe KI-Todo neu
        erzeugt wird, und das Aufgabenlog kann die Ablehnung samt
        Begründung anzeigen. Audit-Eintrag analog:meth:`record_feedback`.

        Args:
            task_id: UUID der Aufgabe.
            reason: Optionale Begründung des Users.
        """
        task = self._repo.load_task(task_id)
        if not task:
            return
        task.status = "dismissed"
        task.dismissed_reason = reason.strip()
        task.done_at = ""
        task.done_note = ""
        task.updated_at = _now_iso()
        self._repo.save_task(task)
        AuditLogger().log_action(
            "TASK_DISMISSED",
            details={
                "task_id": task_id,
                "source_tool": task.source_tool,
                "dedup_key": task.dedup_key,
                "has_reason": bool(task.dismissed_reason),
            },
            tool="mainpage",
        )
        logger.debug("Task abgelehnt: %s", task_id)

    def update_task(self, task: Task) -> None:
        """Persistiert Feld-Änderungen einer bestehenden Aufgabe.

        Ersetzt den früheren GUI-Direktzugriff auf ``_repo.save_task``
        (Schichtverletzung). Setzt ``updated_at`` automatisch.

        Args:
            task: Geänderte Task-Instanz.
        """
        task.updated_at = _now_iso()
        self._repo.save_task(task)
        logger.debug("Task aktualisiert: %s", task.id)

    def delete_task(self, task_id: str) -> None:
        """Löscht eine Aufgabe dauerhaft.

        Args:
            task_id: UUID der Aufgabe.
        """
        self._repo.delete_task(task_id)
        logger.debug("Task geloescht: %s", task_id)

    def auto_complete_task(self, task_id: str, note: str) -> None:
        """Erledigt eine Aufgabe automatisch (Reconciliation).

        Guard: NUR Tasks in ``open``/``in_progress`` werden angefasst —
        ``dismissed`` und ``done`` sind tabu (doppeltes Netz zusätzlich
        zur Kandidaten-Query der Reconciliation). Setzt ``done_note``,
        schreibt einen Journal- und einen Audit-Eintrag.

        Args:
            task_id: UUID der Aufgabe.
            note: Maschinelle Begründung (z. B. "Update installiert").
        """
        task = self._repo.load_task(task_id)
        if not task or task.status not in ("open", "in_progress"):
            return
        now = _now_iso()
        task.status = "done"
        task.done_at = now
        task.done_note = note
        task.dismissed_reason = ""
        task.updated_at = now
        self._repo.save_task(task)
        # Audit VOR dem Journal-Write: schlägt das Journal fehl, bleibt
        # der Audit-Trail trotzdem lückenlos (Task ist bereits done und
        # taucht im nächsten Lauf nicht mehr als Kandidat auf).
        AuditLogger().log_action(
            "TASK_AUTO_COMPLETED",
            details={
                "task_id": task_id,
                "source_tool": task.source_tool,
                "dedup_key": task.dedup_key,
            },
            tool="mainpage",
        )
        self._journal.add_task_auto_done(task, note)
        logger.debug("Task automatisch erledigt: %s", task_id)

    def get_active_auto_tasks(self, source_tool: str) -> list[Task]:
        """Gibt offene/laufende Auto-Tasks eines Quell-Tools zurück.

        Kandidatenliste der Reconciliation.

        Args:
            source_tool: Tool-Bezeichner (z. B. ``"patch_monitor"``).

        Returns:
            Auto-Tasks in ``open``/``in_progress``.
        """
        return self._repo.load_tasks_by_source_tool(source_tool)

    def get_completed_auto_tasks(self, source_tool: str) -> list[Task]:
        """Gibt erledigte Auto-Tasks eines Quell-Tools zurück.

        Reopen-Kandidaten der Reconciliation: erledigte Tasks,
        deren Finding wieder aktiv ist, kommen zurück aufs Board.
        ``dismissed`` ist bewusst NICHT enthalten (User-Entscheidung).

        Args:
            source_tool: Tool-Bezeichner (z. B. ``"patch_monitor"``).

        Returns:
            Auto-Tasks mit Status ``done``.
        """
        return self._repo.load_tasks_by_source_tool(
            source_tool, statuses=("done",)
        )

    def get_task_log(self, limit: int = 200) -> list[Task]:
        """Gibt die Aufgaben-Historie (erledigt + abgelehnt) zurück.

        Args:
            limit: Maximale Anzahl Einträge.

        Returns:
            Historien-Tasks, neueste zuerst.
        """
        return self._repo.load_task_history(limit=limit)

    def create_auto_task(
        self,
        title: str,
        tool_name: str,
        description: str = "",
        klient: str = "",
        urgency: str = "mittel",
        evidence_refs: list[dict] | None = None,
        dedup_key: str = "",
        priority: str = "normal",
    ) -> Task:
        """Erstellt automatische Aufgabe aus FINLAI-Aktion.

        Wird von anderen Tools (typisch:class:`KiTodoService`) aufgerufen,
        wenn ein Finding eine Aktion erfordert.

        **Idempotenz** (Sprint S2a): Wird ein nicht-leerer ``dedup_key``
        übergeben und existiert bereits eine Task mit identischem Schlüssel
        in der DB, wird die bestehende Task zurückgeliefert — keine
        Duplikate. Damit kann derselbe Scan mehrfach laufen, ohne dass
        die Kanban-Spalten überfluten.

        Args:
            title: Kurztitel der Aufgabe.
            tool_name: Name des aufrufenden Tools.
            description: Optionale Beschreibung.
            klient: Klientenname.
            urgency: Effort-Klassifikation aus der Regel-Engine.
            evidence_refs: Quellen-Referenzen für Drill-Down.
            dedup_key: Stabile Hash-Referenz; leer = kein Dedup.
            priority: Priorität (``"low"``/``"normal"``/``"high"``). Default
                ``"normal"``; ``"high"`` markiert die Task im Kanban als
                kritisch (:meth:`create_critical_task`).

        Returns:
            Neu erstellte Task-Instanz **oder** die bestehende Task mit
            identischem ``dedup_key`` (``find_task_by_dedup_key`` matcht
            statusunabhängig — auch eine bereits erledigte Task verhindert
            ein Duplikat).
        """
        if dedup_key:
            existing = self._repo.find_task_by_dedup_key(dedup_key)
            if existing is not None:
                logger.debug(
                    "create_auto_task: Dedup-Hit fuer %s — gebe bestehende "
                    "Task %s zurueck",
                    dedup_key,
                    existing.id,
                )
                return existing
        return self.create_task(
            title=title,
            description=description,
            category="tool",
            klient=klient,
            source="auto",
            source_tool=tool_name,
            priority=priority,
            urgency=urgency,
            evidence_refs=evidence_refs,
            dedup_key=dedup_key,
        )

    def create_critical_task(
        self,
        title: str,
        *,
        description: str = "",
        source_tool: str = "",
        dedup_key: str = "",
        klient: str = "",
        urgency: str = "mittel",
        evidence_refs: list[dict] | None = None,
    ) -> Task:
        """Erstellt eine kritische automatische Aufgabe (``priority="high"``).

        Dünner Wrapper um:meth:`create_auto_task` mit fest gesetzter
        Priorität — damit landet der Hinweis im Homescreen-Kanban als
        kritisches Thema (``priority="high"`` → Critical-Darstellung im
        ``TaskboardWidget``). Erbt die Dedup-Idempotenz von
:meth:`create_auto_task`: bei identischem ``dedup_key`` wird die
        bestehende Task zurückgeliefert statt eine zweite anzulegen.

        Eingeführt für (Patch-Monitor-Onboarding: einmaliger Hinweis
        statt Dauerprompt).

        Args:
            title: Kurztitel der Aufgabe.
            description: Optionale Beschreibung.
            source_tool: Name des aufrufenden Tools.
            dedup_key: Stabile Hash-Referenz für die Einmaligkeit; leer =
                kein Dedup.
            klient: Klientenname.
            urgency: Effort-Klassifikation aus der Regel-Engine.
            evidence_refs: Quellen-Referenzen für Drill-Down.

        Returns:
            Neu erstellte Task-Instanz **oder** die bestehende Task, falls
            der ``dedup_key`` bereits eine Task hat.
        """
        return self.create_auto_task(
            title=title,
            tool_name=source_tool,
            description=description,
            klient=klient,
            urgency=urgency,
            evidence_refs=evidence_refs,
            dedup_key=dedup_key,
            priority="high",
        )

    # -----------------------------------------------------------------------
    # KI-Todo-Feedback (Sprint S2b)
    # -----------------------------------------------------------------------

    def record_feedback(self, task_id: str, helpful: bool) -> None:
        """Loggt User-Feedback zu einer KI-Todo im Audit-Log.

        Wird vom Mainpage-UI (``_TaskCard``-Buttons "Hilfreich" /
        "Nicht hilfreich") aufgerufen, sobald der User ein Urteil abgibt.
        Persistenz nur als Audit-Eintrag — bewusst nicht auf der Task
        selbst, damit nachträgliche Trainings-Datensätze rekonstruierbar
        bleiben (AI_TODO 5.7 Cool-Down).

        Args:
            task_id: UUID der bewerteten Task. Existiert die Task nicht
                mehr (z. B. bereits gelöscht), wird der Eintrag trotzdem
                geschrieben — der Audit-Trail soll lückenlos bleiben.
            helpful: ``True`` = Hilfreich, ``False`` = Nicht hilfreich.
        """
        task = self._repo.load_task(task_id)
        details: dict[str, object] = {
            "task_id": task_id,
            "helpful": helpful,
        }
        if task is not None:
            details["source_tool"] = task.source_tool
            details["urgency"] = task.urgency
            details["dedup_key"] = task.dedup_key
        AuditLogger().log_action(
            "KI_TODO_FEEDBACK",
            details=details,
            tool="ki_todo",
        )
        logger.debug(
            "KI-Todo-Feedback geloggt: task=%s helpful=%s", task_id, helpful
        )

    # -----------------------------------------------------------------------
    # Board-Aggregation
    # -----------------------------------------------------------------------

    def get_board_data(self) -> dict:
        """Gibt Task-Board Daten zurück.

        Returns:
            Dict mit Schlüsseln ``open``, ``in_progress``, ``done_today``.
        """
        return {
            "open": self._repo.load_tasks(status="open"),
            "in_progress": self._repo.load_tasks(status="in_progress"),
            "done_today": self._get_done_today(),
        }

    def _get_done_today(self) -> list[Task]:
        """Gibt alle am heutigen LOKALEN Tag erledigten Aufgaben zurück.

        ``done_at`` wird in UTC gespeichert (:func:`_now_iso`). Ein direkter
        Präfix-Vergleich mit dem lokalen ``date.today`` würde an der
        Tagesgrenze fehlschlagen (z. B. ``23:30`` UTC ist lokal bereits der
        Folgetag). Darum wird jedes ``done_at`` in die lokale Zeitzone
        konvertiert und erst dann das Datum verglichen.

        Returns:
            Liste der ``done``-Tasks mit ``done_at`` am heutigen lokalen Datum.
        """
        today = date.today()
        all_done = self._repo.load_tasks(status="done")
        return [
            t
            for t in all_done
            if t.done_at
            and datetime.fromisoformat(t.done_at).astimezone().date() == today
        ]
