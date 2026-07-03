"""ki_todo_emitter — Bridge zwischen Scanner-Services und KiTodoService.

Vereinheitlicht den Hook-Pfad: nach erfolgreichem Scan ruft jeder Scanner-
Service ``KiTodoEmitter.emit(findings)`` mit den vom tool-spezifischen
Adapter konvertierten ``FindingInput``-Objekten. Der Emitter:

- Lazy-baut den:class:`KiTodoService` (mit Default-Regeln) — falls die
  Initialisierung scheitert (z. B. SQLCipher fehlt), bleibt der Hook
  ein No-op und der Scan ist nicht beeinträchtigt.
- Schluckt jede Exception aus:func:`KiTodoService.evaluate_findings`,
  loggt sie auf WARNING — KI-Todo-Generierung darf NIE einen Scan
  brechen (Information-Value-Prinzip: Tool-Hauptfunktion hat Vorrang).

Schichtzugehoerigkeit: ``core/storytelling/`` (gemeinsam mit
``narrative_builder`` + ``finding_templates`` + ``schemas``).

**Architektur-Hinweis P2, 2026-05-09):** ``_lazy_service`` macht
einen Lazy-Import aus ``tools.mainpage.*``. In strenger hexagonaler Lesart
verletzt das das ``core``-darf-nicht-tools-importieren-Prinzip. Pragmatisch
akzeptiert weil:

  1. Lazy-Import (Modul-Top-Level kennt ``tools`` nicht — kein zirkulaerer
     Import beim Bootstrap).
  2. Best-effort: Bei ImportError bleibt der Emitter No-op (kein Hard-Dep).
  3. Mainpage ist die "Output-Senke" der Storytelling-Engine — strukturell
     gehoert sie semantisch zu ``core/storytelling``, lebt aber als Tool
     fuer GUI-Kapselung.

Eine saubere Loesung waere ``KiTodoEmitter`` als ABC + dynamischer
Service-Registry, aber das ist ein Architektur-Refactor (eigener Sprint).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable

from core.logger import get_logger
from core.storytelling.schemas import FindingInput

log = get_logger(__name__)


class KiTodoEmitter:
    """Lazy-Bridge zwischen Scanner-Services und KiTodoService.

    Pattern pro Scanner-Service:

.. code-block:: python

        from core.storytelling.ki_todo_emitter import KiTodoEmitter

        class MyScannerService:
            def __init__(self,..., ki_todo_emitter: KiTodoEmitter | None = None):
                self._ki_emitter = ki_todo_emitter or KiTodoEmitter

            def run_scan(self, target):
                result = self._scan(target)
                # Hook nach Scan-Complete:
                findings = my_findings_to_ki_inputs(result)
                self._ki_emitter.emit(findings)
                return result

    Der Adapter ``my_findings_to_ki_inputs(result)`` ist tool-spezifisch und
    lebt im jeweiligen ``tools/<tool>/application/``-Modul.
    """

    def __init__(self) -> None:
        """Baut den Emitter ohne Service — Service wird lazy initialisiert."""
        self._service: object | None = None
        self._init_attempted = False

    def emit(
        self,
        findings: Iterable[FindingInput],
        *,
        reconcile_tool: str | None = None,
    ) -> None:
        """Reicht die Findings an den:class:`KiTodoService` weiter.

        No-op falls der Service nicht initialisierbar ist (z. B. mainpage-DB
        fehlt). Exceptions aus dem Service werden geschluckt und auf
        WARNING geloggt — KI-Todo-Generierung darf nie einen Scan brechen.

        Args:
            findings: Iterable von:class:`FindingInput`-Objekten. Leeres
                Iterable ist No-op — AUSSER ``reconcile_tool`` ist gesetzt
: "alle Updates installiert" muss die offenen Tasks
                schließen können).
            reconcile_tool: Tool-Bezeichner für den Voll-Sync
                (:meth:`KiTodoService.sync_findings`). NUR setzen, wenn
                ``findings`` die VOLLSTÄNDIGE aktuelle Liste des Tools ist
                (kein Delta!) — sonst werden offene Tasks fälschlich
                auto-erledigt. ``None`` = altes Verhalten (nur anlegen).
        """
        finding_list = list(findings)
        if not finding_list and reconcile_tool is None:
            return
        service = self._lazy_service()
        if service is None:
            return
        try:
            if reconcile_tool is not None:
                tasks = service.sync_findings(  # type: ignore[attr-defined]
                    reconcile_tool, finding_list
                )
            else:
                tasks = service.evaluate_findings(finding_list)  # type: ignore[attr-defined]
            log.debug(
                "KiTodoEmitter: %d findings -> %d tasks (reconcile=%s)",
                len(finding_list),
                len(tasks),
                reconcile_tool or "-",
            )
        except Exception as exc:  # noqa: BLE001 -- Hook darf NIE einen Scan brechen
            log.warning(
                "KiTodoEmitter: Hook fehlgeschlagen (%s) — %d findings verworfen",
                type(exc).__name__,
                len(finding_list),
            )

    def _lazy_service(self) -> object | None:
        """Baut den:class:`KiTodoService` einmalig, cached oder None."""
        if self._init_attempted:
            return self._service
        self._init_attempted = True
        try:
            from tools.mainpage.application.journal_service import (  # noqa: PLC0415
                JournalService,
            )
            from tools.mainpage.application.ki_todo_service import (  # noqa: PLC0415
                KiTodoService,
            )
            from tools.mainpage.application.task_service import (
                TaskService,  # noqa: PLC0415
            )
            from tools.mainpage.data.mainpage_repository import (  # noqa: PLC0415
                MainpageRepository,
            )

            repo = MainpageRepository()
            journal = JournalService(repo)
            tasks = TaskService(repo, journal)
            self._service = KiTodoService.for_default_rules(task_service=tasks)
        except Exception as exc:  # noqa: BLE001 -- Setup-Fehler dürfen Scan nicht brechen
            log.info(
                "KiTodoEmitter: Service-Init fehlgeschlagen (%s) — Hook bleibt No-op",
                type(exc).__name__,
            )
            self._service = None
        return self._service
