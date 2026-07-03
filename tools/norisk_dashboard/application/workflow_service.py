"""workflow_service — Anwendungslogik des Cockpit-Workflow-Tabs, Phase 2).

Verbindet die statische Checkliste (``domain/workflow_definition``) mit dem
persistierten Fortschritt (``data/workflow_progress_repository``) und liefert der
GUI eine fertige Sicht pro Subjekt:

* Subjekt-Gating: eigenes System (SELF) vs. Kunde (kein technisches Scannen);
  fuer SELF zusaetzlich das W1-Profil-Gating (cert/api/dependency nur mit
  passendem Profil-Flag), reversibel ueber ``gating_enabled``.
* Merge von Definition + Status/Notiz zu:class:`WorkflowStepView`.
* Aggregierter Fortschritt (:class:`WorkflowSummary`) fuer die Kopf-Anzeige.

Der Repository-Zugriff laeuft ueber das:class:`_ProgressStore`-Protocol — die
application-Schicht definiert den Port, den die data-Schicht erfuellt (kein
application->data-Import).

Schicht: ``application/`` — kein PySide6, kein direkter DB-/SQL-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from core.security_subject.models import Subject, SubjectKind
from tools.norisk_dashboard.domain.workflow_definition import steps_for_kind
from tools.norisk_dashboard.domain.workflow_models import (
    APPLIES_KUNDE,
    APPLIES_SELF,
    WorkflowStepDef,
    WorkflowStepProgress,
    WorkflowStepStatus,
    WorkflowSummary,
    compute_summary,
    normalize_status,
)


class _ProgressStore(Protocol):
    """Port: der Fortschritts-Speicher, den der Service benoetigt (data erfuellt ihn)."""

    def get_progress(self, subject_id: str) -> dict[str, WorkflowStepProgress]: ...

    def set_status(
        self,
        subject_id: str,
        step_key: str,
        status: str | WorkflowStepStatus,
        *,
        note: str | None = None,
    ) -> None: ...

    def set_note(self, subject_id: str, step_key: str, note: str) -> None: ...

    def reset(self, subject_id: str) -> int: ...


@dataclass(frozen=True)
class WorkflowStepView:
    """Ein Schritt mit seinem aktuellen Fortschritt (fuer die GUI)."""

    step: WorkflowStepDef
    status: WorkflowStepStatus
    note: str


@dataclass(frozen=True)
class WorkflowView:
    """Die komplette Workflow-Sicht eines Subjekts (fuer den Cockpit-Tab)."""

    subject_id: str
    subject_name: str
    is_self: bool
    steps: tuple[WorkflowStepView, ...]
    summary: WorkflowSummary


class WorkflowService:
    """Orchestriert Checkliste + Fortschritt pro Subjekt.

    Args:
        repository: Fortschritts-Speicher (:class:`_ProgressStore`).
        gating_enabled: Ob das W1-Profil-Gating fuer das eigene System greift
            (spiegelt ``UISettings.profile_gating_enabled`` — „Alle Module
            anzeigen" hebt es auf). Bei Kunden greift Gating ohnehin nie.
    """

    def __init__(
        self, repository: _ProgressStore, *, gating_enabled: bool = True
    ) -> None:
        self._repo = repository
        self._gating_enabled = gating_enabled

    # ------------------------------------------------------------------
    # Lesen
    # ------------------------------------------------------------------

    def steps_for_subject(self, subject: Subject) -> list[WorkflowStepDef]:
        """Die fuer ein Subjekt geltenden Schritte (applies_to + W1-Gating).

        Args:
            subject: Das aktuell gewaehlte Subjekt (eigenes System oder Kunde).

        Returns:
            Nach ``order`` sortierte Schritte; bei SELF ohne die profilbedingt
            ausgeblendeten Scan-Schritte (wenn Gating aktiv).
        """
        is_self = subject.kind == SubjectKind.EIGENES
        kind = APPLIES_SELF if is_self else APPLIES_KUNDE
        steps = list(steps_for_kind(kind))
        if is_self and self._gating_enabled:
            steps = [s for s in steps if self._passes_gating(subject, s)]
        return steps

    def _passes_gating(self, subject: Subject, step: WorkflowStepDef) -> bool:
        """Tri-state-Gating (0/1/None): nur ``0`` blendet den Schritt aus."""
        if not step.gating_key:
            return True
        flag = getattr(subject, step.gating_key, None)
        return flag != 0

    def get_view(self, subject: Subject) -> WorkflowView:
        """Baut die komplette Workflow-Sicht (Schritte + Status/Notiz + Summary).

        Args:
            subject: Das aktuell gewaehlte Subjekt.

        Returns:
            Die:class:`WorkflowView` fuer die GUI.
        """
        steps = self.steps_for_subject(subject)
        progress = self._repo.get_progress(subject.subject_id)
        views: list[WorkflowStepView] = []
        statuses: dict[str, str] = {}
        for step in steps:
            entry = progress.get(step.step_key)
            status = (
                normalize_status(entry.status)
                if entry is not None
                else WorkflowStepStatus.OFFEN
            )
            note = entry.note if entry is not None else ""
            views.append(WorkflowStepView(step=step, status=status, note=note))
            statuses[step.step_key] = status.value
        summary = compute_summary(steps, statuses)
        return WorkflowView(
            subject_id=subject.subject_id,
            subject_name=subject.name,
            is_self=subject.kind == SubjectKind.EIGENES,
            steps=tuple(views),
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Schreiben (delegiert an den Speicher)
    # ------------------------------------------------------------------

    def set_status(
        self,
        subject_id: str,
        step_key: str,
        status: str | WorkflowStepStatus,
        *,
        note: str | None = None,
    ) -> None:
        """Setzt den Status eines Schritts (siehe Repository)."""
        self._repo.set_status(subject_id, step_key, status, note=note)

    def set_note(self, subject_id: str, step_key: str, note: str) -> None:
        """Setzt die Notiz eines Schritts."""
        self._repo.set_note(subject_id, step_key, note)

    def reset(self, subject_id: str) -> int:
        """Setzt den kompletten Fortschritt eines Subjekts zurueck."""
        return self._repo.reset(subject_id)


__all__ = ["WorkflowService", "WorkflowStepView", "WorkflowView"]
