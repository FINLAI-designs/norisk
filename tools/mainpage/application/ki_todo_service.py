"""ki_todo_service — Erzeugt KI-Todos aus Findings (Sprint S2a).

Public Eintritts-Funktion:meth:`KiTodoService.evaluate_findings`. Wird
von Tools aufgerufen, die einen Scan abgeschlossen haben — typisch nach
einem ``*_SCAN_COMPLETE``-Audit-Event. Pipeline pro Finding:

  1. **Match**: Regel-Engine liefert eine oder mehrere
:class:`core.rules.models.RuleAction`-Treffer.
  2. **Storytelling**: Storytelling-Engine rendert Story
     (Headline, Erklärung, Aktion) — Patrick-Tonalität aus Sprint S1a.
  3. **Dedup**: Stabile Hash-Referenz aus
     ``(tool, finding_type, evidence_id)``. Bestehende Tasks werden
     nicht dupliziert.
  4. **Persistenz**: ``TaskService.create_auto_task`` schreibt die Task
     mit ``urgency`` (aus dem Klassifikator), ``evidence_refs`` und
     ``dedup_key`` in die DB.

Schichtzugehörigkeit: application/ — keine GUI-Imports, keine direkten
DB-Aufrufe.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from core.logger import get_logger
from core.rules.models import RuleAction
from core.rules.rule_engine import RuleEngine
from core.storytelling.narrative_builder import (
    TemplateNotFoundError,
    build_story,
)
from core.storytelling.schemas import FindingInput
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.domain.models import Task

log = get_logger(__name__)

# maschinelle done_note-Texte der Reconciliation. RESOLVED =
# das Quell-Finding ist komplett verschwunden (Update installiert /
# Software entfernt / vom Patchen ausgenommen / Befund behoben).
# SUPERSEDED = dasselbe Subjekt (evidence_id) ist weiter aktiv, aber
# unter neuem finding_type — die Nachfolger-Task wurde im selben
# Sync-Lauf angelegt.
_NOTE_RESOLVED = (
    "FINLAI hat das für dich abgehakt — das Update ist installiert "
    "oder der Befund ist nicht mehr offen."
)
_NOTE_SUPERSEDED = (
    "FINLAI hat das für dich abgehakt — eine neue Einschätzung "
    "ersetzt diese Aufgabe."
)


class KiTodoService:
    """Erzeugt regel-basierte KI-Todos aus rohen Findings.

    Args:
        task_service: Bestehender:class:`TaskService` — wir nutzen
            seine ``create_auto_task``-Methode (mit Dedup-Logik).
        rule_engine: Bereits geladene:class:`RuleEngine`-Instanz.
            Tests übergeben eine kuratierte Engine; Produktion nutzt
:meth:`for_default_rules`.
    """

    def __init__(
        self,
        task_service: TaskService,
        rule_engine: RuleEngine,
    ) -> None:
        self._tasks = task_service
        self._engine = rule_engine

    @classmethod
    def for_default_rules(
        cls,
        task_service: TaskService,
        rules_dir: Path | None = None,
    ) -> KiTodoService:
        """Convenience-Builder mit den Default-Regeln aus ``configs/rules/``.

        Args:
            task_service: TaskService-Instanz.
            rules_dir: Optionaler abweichender Regel-Ordner (Tests).
                ``None`` → auflösen relativ zum Repository-Root.
        """
        if rules_dir is None:
            # Repository-Root = dreimal nach oben (file → application →
            # mainpage → tools → repo).
            rules_dir = Path(__file__).resolve().parents[3] / "configs" / "rules"
        engine = RuleEngine.from_directory(rules_dir)
        return cls(task_service=task_service, rule_engine=engine)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_findings(self, findings: list[FindingInput]) -> list[Task]:
        """Verarbeitet eine Findings-Liste und erzeugt/dedupliziert Tasks.

        Args:
            findings: Normalisierte Findings (typisch ein Scan-Lauf eines
                Tools). Reihenfolge wird beibehalten.

        Returns:
            Liste der **resultierenden** Tasks — kann sowohl neu
            erzeugte als auch (per Dedup-Hit) bestehende enthalten.
            Findings ohne Regel-Match oder ohne Storytelling-Template
            werden geloggt und übersprungen.
        """
        results: list[Task] = []
        for finding in findings:
            actions = self._engine.evaluate(finding)
            if not actions:
                log.debug(
                    "KI-Todo: keine Regel matcht %s/%s",
                    finding.tool,
                    finding.finding_type,
                )
                continue
            for action in actions:
                task = self._task_from_action(finding, action)
                if task is not None:
                    results.append(task)
        return results

    def sync_findings(
        self, tool: str, findings: list[FindingInput]
    ) -> list[Task]:
        """Voll-Sync: Tasks anlegen/deduplizieren UND Bestand abgleichen.

        Erweitert:meth:`evaluate_findings` um die Reconciliation:
        offene Auto-Tasks des Tools, deren Quell-Finding nicht mehr in
        der aktuellen Liste auftaucht, werden automatisch erledigt;
        Tasks mit weiterhin aktivem Finding bekommen frische Titel/
        Beschreibungen (Stale-Version-Fix).

        **Vorbedingung:** ``findings`` MUSS die VOLLSTÄNDIGE aktuelle
        Findings-Liste des Tools sein (kein Delta!) — sonst werden
        offene Tasks fälschlich als erledigt markiert. Beim
        patch_monitor ist das erfüllt (``load_from_db`` rekonstruiert
        den kompletten Bestand pro Scan).

        Args:
            tool: Tool-Bezeichner (z. B. ``"patch_monitor"``).
            findings: Vollständige aktuelle Findings des Tools.

        Returns:
            Resultierende Tasks aus:meth:`evaluate_findings`.
        """
        results = self.evaluate_findings(findings)
        self._reconcile(tool, findings)
        return results

    # ------------------------------------------------------------------
    # Interna
    # ------------------------------------------------------------------

    def _reconcile(self, tool: str, findings: list[FindingInput]) -> None:
        """Gleicht aktive Auto-Tasks gegen die aktuellen Findings ab.

        Arbeitet auf den ROHEN Findings (nicht regel-gefiltert):
        konservativ bleibt eine Task offen, solange ihr Finding
        existiert — auch wenn aktuell keine Regel mehr matcht.

        Dismissed-Schutz ist dreifach: (a) Kandidaten-Query liefert nur
        ``open``/``in_progress`` bzw. ``done``, (b) ``auto_complete_task``
        guarded selbst, (c) der Dedup-Key verhindert Neuanlage (Bestand).

        Args:
            tool: Tool-Bezeichner.
            findings: Vollständige aktuelle Findings des Tools.
        """
        # Defensiv: nur Findings DIESES Tools verwenden — eine gemischte
        # Liste würde sonst die Erledigt-/Supersede-Heuristik verfälschen.
        findings = [f for f in findings if f.tool == tool]
        active_by_key = {
            compute_dedup_key(
                tool=f.tool,
                finding_type=f.finding_type,
                evidence_id=f.evidence_id,
            ): f
            for f in findings
        }
        active_evidence = {f.evidence_id for f in findings}
        for task in self._tasks.get_active_auto_tasks(tool):
            if not task.dedup_key or not task.evidence_refs:
                # Nur Finding-gestützte Tasks abgleichen: ohne dedup_key
                # (Alt-Bestand) oder ohne evidence_refs (z. B. der
                # Scan-Reminder) gibt es kein Quell-Finding, dessen
                # Verschwinden eine Auto-Erledigung rechtfertigen würde.
                continue
            finding = active_by_key.get(task.dedup_key)
            if finding is not None:
                self._refresh_stale_task(task, finding)
                continue
            # Finding weg: Unterscheiden, ob das Subjekt noch aktiv ist
            # (Recommendation-Wechsel -> neuer finding_type -> neuer Key).
            task_evidence = {
                ref.get("finding_id")
                for ref in task.evidence_refs
                if isinstance(ref, dict)
            }
            note = (
                _NOTE_SUPERSEDED
                if task_evidence & active_evidence
                else _NOTE_RESOLVED
            )
            self._tasks.auto_complete_task(task.id, note=note)

        # Review-P1: Wiederkehrende Findings. Der versions-lose
        # dedup_key blockiert sonst JEDE Folge-Task derselben Software —
        # eine erledigte Task, deren Finding WIEDER aktiv ist (z. B.
        # naechstes Update Monate spaeter), kommt zurueck aufs Board.
        # Bewusst auch fuer manuell erledigte Tasks: das Board soll die
        # Realitaet zeigen; dauerhaftes Ausblenden = "Aufgabe ablehnen"
        # (dismissed bleibt tabu).
        for task in self._tasks.get_completed_auto_tasks(tool):
            if not task.dedup_key or not task.evidence_refs:
                continue
            finding = active_by_key.get(task.dedup_key)
            if finding is None:
                continue
            self._tasks.reopen_task(task.id)
            reopened = self._tasks.get_task(task.id)
            if reopened is not None:
                self._refresh_stale_task(reopened, finding)
            log.info(
                "Reconciliation: Finding wieder aktiv — Task %s reopened",
                task.id,
            )

    def _refresh_stale_task(self, task: Task, finding: FindingInput) -> None:
        """Frischt Titel/Beschreibung einer offenen Task auf.

        Der ``dedup_key`` ignoriert die Version — wenn z. B. eine neuere
        ``available_version`` erscheint, blieb der Karten-Titel bisher
        auf der alten Version stehen. Re-rendert die Story und speichert
        NUR bei tatsächlicher Differenz (kein unnötiges updated_at).

        Args:
            task: Aktive Auto-Task mit weiterhin existierendem Finding.
            finding: Das aktuelle Quell-Finding.
        """
        try:
            story = build_story(finding)
        except TemplateNotFoundError:
            log.debug(
                "Reconciliation: kein Template fuer (%s, %s) — Titel-"
                "Refresh uebersprungen",
                finding.tool,
                finding.finding_type,
            )
            return
        description = f"{story.explanation}\n\n{story.action}"
        if task.title == story.headline and task.description == description:
            return
        task.title = story.headline
        task.description = description
        self._tasks.update_task(task)

    def _task_from_action(
        self,
        finding: FindingInput,
        action: RuleAction,
    ) -> Task | None:
        """Erzeugt eine Task aus einer Regel-Aktion + dem Quell-Finding."""
        try:
            story = build_story(finding)
        except TemplateNotFoundError:
            # Regel matcht, aber Storytelling-Template fehlt — wird in
            # späteren Sprints (Roll-out auf 25 Templates) ergänzt; hier
            # überspringen statt mit halben Daten zu schreiben.
            log.warning(
                "KI-Todo: Regel '%s' matcht, aber Storytelling-Template "
                "fuer (%s, %s) fehlt — uebersprungen",
                action.rule_id,
                finding.tool,
                finding.finding_type,
            )
            return None

        dedup_key = compute_dedup_key(
            tool=finding.tool,
            finding_type=finding.finding_type,
            evidence_id=finding.evidence_id,
        )
        evidence_refs = [
            {
                "tool": finding.tool,
                "finding_id": finding.evidence_id,
            }
        ]
        # Description = Erklärung + leerzeile + Aktion. Ergibt einen
        # selbsterklärenden Karten-Text auf dem Kanban-Board, ohne dass
        # die UI separate Felder kennen muss.
        description = f"{story.explanation}\n\n{story.action}"
        return self._tasks.create_auto_task(
            title=story.headline,
            tool_name=finding.tool,
            description=description,
            urgency=action.urgency,
            evidence_refs=evidence_refs,
            dedup_key=dedup_key,
        )


# ---------------------------------------------------------------------------
# Public Helper
# ---------------------------------------------------------------------------


def compute_dedup_key(tool: str, finding_type: str, evidence_id: str) -> str:
    """Stabiler SHA-256-Hash für die ``Task.dedup_key``-Spalte.

    Wird auch von Tests genutzt, damit sie den erwarteten Key
    deterministisch berechnen können. Das Resultat ist 64 Zeichen Hex.
    """
    raw = f"{tool}|{finding_type}|{evidence_id}".encode()
    return hashlib.sha256(raw).hexdigest()
