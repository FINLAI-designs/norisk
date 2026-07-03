"""workflow_models — Domain-Modelle fuer den Cockpit-Workflow-Tab.

Der Workflow-Tab ist ein gefuehrter Nutzungs-Leitfaden (Checkliste) fuer die
richtige Reihenfolge der Tool-Nutzung. Diese Datei enthaelt die reinen
Domain-Bausteine — keine DB-, GUI- oder Service-Importe:

*:class:`WorkflowStepStatus` — der veraenderbare Status eines Schritts.
*:class:`WorkflowStepDef` — die (statische) Definition eines Schritts
  (Reihenfolge, Ziel-Tool, Gating). Die konkrete Schrittliste steht in
:mod:`tools.norisk_dashboard.domain.workflow_definition`.
*:class:`WorkflowStepProgress` — der persistierte Fortschritt (Status + Notiz)
  eines Schritts fuer EIN Subjekt.
*:class:`WorkflowSummary` +:func:`compute_summary` — der aggregierte
  Fortschritt (Prozent) fuer die Kopf-Anzeige.

Schicht: ``domain/`` — importiert nur die Standardbibliothek.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

#: Ziel-Kennung „gilt fuer welches Subjekt": eigenes System, Kunde, oder beide.
APPLIES_SELF: str = "self"
APPLIES_KUNDE: str = "kunde"
APPLIES_BOTH: str = "both"


class WorkflowStepStatus(StrEnum):
    """Der veraenderbare Bearbeitungs-Status eines Workflow-Schritts.

    Effekt: Der Wert wird 1:1 in ``workflow_step_progress.status`` persistiert
    (CHECK-Constraint dort spiegelt exakt diese Werte §2). Eine
    Aenderung hier verlangt eine additive Migration des CHECK-Constraints.
    """

    OFFEN = "offen"
    IN_ARBEIT = "in_arbeit"
    ERLEDIGT = "erledigt"
    UEBERSPRUNGEN = "uebersprungen"
    NICHT_RELEVANT = "nicht_relevant"


#: Erlaubte Status-Werte als Set (Repository-Validierung + CHECK-Spiegel).
VALID_STATUS: frozenset[str] = frozenset(s.value for s in WorkflowStepStatus)


def normalize_status(value: str | WorkflowStepStatus) -> WorkflowStepStatus:
    """Wandelt einen rohen Statuswert in:class:`WorkflowStepStatus`.

    Args:
        value: Enum oder roher String (Qt liefert StrEnum-userData oft als
            plain ``str``).

    Returns:
        Der passende:class:`WorkflowStepStatus`.

    Raises:
        ValueError: Wenn ``value`` kein gueltiger Status ist.
    """
    if isinstance(value, WorkflowStepStatus):
        return value
    return WorkflowStepStatus(str(value))


@dataclass(frozen=True)
class WorkflowStepDef:
    """Statische Definition eines Workflow-Schritts (Produkt-Content, keine DB).

    Attributes:
        step_key: Stabiler, code-seitiger Schluessel (z. B. ``"scan_system"``).
            Effekt: Wird als Fremd-Schluessel in ``workflow_step_progress.step_key``
            (Status + Notiz) verwendet — Umbenennen verwaist gespeicherten
            Fortschritt, daher stabil halten.
        phase: Gruppen-Ueberschrift fuer die GUI (Phasen-Pfad).
        titel: Anzeigename des Schritts (Sie-Form).
        beschreibung: Ein Satz — warum dieser Schritt an dieser Stelle steht.
        nav_key: Navigations-/Deeplink-Schluessel zum Ziel-Tool (Router-Alias
            loest z. B. ``"customer_audit"`` in den passenden Sub-Tab auf).
        applies_to::data:`APPLIES_SELF` /:data:`APPLIES_KUNDE` /:data:`APPLIES_BOTH`.
        gating_key: Optionaler W1-Profil-Flag-Schluessel
            (``core.security_subject.w1_profil.GATING_KEY_*``). Ist das Flag am
            eigenen Subjekt ``0``, blendet der Service den Schritt aus.
        order: Sortier-Position (aufsteigend).
    """

    step_key: str
    phase: str
    titel: str
    beschreibung: str
    nav_key: str
    applies_to: str = APPLIES_SELF
    gating_key: str | None = None
    order: int = 0


@dataclass(frozen=True)
class WorkflowStepProgress:
    """Persistierter Fortschritt eines Schritts fuer EIN Subjekt.

    Attributes:
        subject_id: Soft-Key auf ``Subject`` (eigenes System = regulaere UUID).
        step_key: Verweist auf:attr:`WorkflowStepDef.step_key`.
        status: Roher Statuswert (:class:`WorkflowStepStatus`).
        note: Freitext-Notiz (kann PII enthalten -> at-rest verschluesselt).
        updated_at: ISO-8601-Zeitstempel der letzten Aenderung (UTC).
    """

    subject_id: str
    step_key: str
    status: str = WorkflowStepStatus.OFFEN.value
    note: str = ""
    updated_at: str = ""


@dataclass(frozen=True)
class WorkflowSummary:
    """Aggregierter Fortschritt fuer die Kopf-Anzeige.

    ``percent_done`` folgt dem-Entscheid: ``nicht_relevant`` zaehlt weder
    in Zaehler noch Nenner; ``uebersprungen`` zaehlt im Nenner, nicht im Zaehler
    (ein uebersprungener Schritt drueckt also den Fortschritt).
    """

    total: int
    relevant: int
    done: int
    skipped: int
    offen: int
    not_relevant: int
    percent_done: int


def compute_summary(
    steps: Sequence[WorkflowStepDef],
    statuses: Mapping[str, str],
) -> WorkflowSummary:
    """Verdichtet die Schritt-Status zu einer:class:`WorkflowSummary`.

    Args:
        steps: Die fuer das aktuelle Subjekt geltenden Schritte.
        statuses: Abbildung ``step_key -> Statuswert`` (fehlt ein Key, gilt
:attr:`WorkflowStepStatus.OFFEN`).

    Returns:
        Die aggregierte:class:`WorkflowSummary`.
    """
    total = len(steps)

    def _status(step: WorkflowStepDef) -> str:
        return statuses.get(step.step_key, WorkflowStepStatus.OFFEN.value)

    not_relevant = sum(
        1 for s in steps if _status(s) == WorkflowStepStatus.NICHT_RELEVANT.value
    )
    relevant = total - not_relevant
    done = sum(1 for s in steps if _status(s) == WorkflowStepStatus.ERLEDIGT.value)
    skipped = sum(
        1 for s in steps if _status(s) == WorkflowStepStatus.UEBERSPRUNGEN.value
    )
    offen = relevant - done - skipped
    percent = round(100 * done / relevant) if relevant else 0
    return WorkflowSummary(
        total=total,
        relevant=relevant,
        done=done,
        skipped=skipped,
        offen=offen,
        not_relevant=not_relevant,
        percent_done=percent,
    )


__all__ = [
    "APPLIES_BOTH",
    "APPLIES_KUNDE",
    "APPLIES_SELF",
    "VALID_STATUS",
    "WorkflowStepDef",
    "WorkflowStepProgress",
    "WorkflowStepStatus",
    "WorkflowSummary",
    "compute_summary",
    "normalize_status",
]
