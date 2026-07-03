"""mode_gate — Fail-closed Provenance-Gate fürs Security-Scoring P0-B).

Spiegelt das Muster aus ``tools.customer_audit.domain.mode_gate``: eine
**gemessene** Hardening-Messung darf NIE einem KUNDEN zugeordnet werden — der
Scanner läuft auf dem Beraterrechner, nicht auf der Mandanten-Maschine
 „Messung ist physikalisch nur SELF" / E2). Kundendaten sind
ausschließlich ``ERFASST`` (manuell eingetragen), nie ``GEMESSEN``.
``SubjectKind`` selbst hält das fest: EIGENES bekommt als einziges Subjekt
technisches Scoring; KUNDE ist „kein technisches Scoring".

Schichtzugehörigkeit: domain/ — pure, keine I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.herkunft import Herkunft
from core.security_subject.models import SubjectKind


class ScoringModeViolationError(RuntimeError):
    """Eine gemessene Hardening-Messung wurde einem Kunden zugeordnet (verboten)."""


def assert_messung_nur_self(
    herkunft: Herkunft, subject_kind: SubjectKind | None
) -> None:
    """Stellt fail-closed sicher, dass ``GEMESSEN`` nur fürs eigene System gilt.

    Args:
        herkunft: Provenance des zu persistierenden Ergebnisses.
        subject_kind: ``SubjectKind`` des Ziel-Subjekts, oder ``None`` wenn
            unbekannt (kein SubjectStore / leeres ``subject_id`` = eigenes
            System, Bestands-/Default-Pfad) — dann kein Verstoß.

    Raises:
        ScoringModeViolationError: Wenn ``herkunft`` ``GEMESSEN`` ist und das
            Subjekt ein ``KUNDE`` ist.
    """
    if herkunft is Herkunft.GEMESSEN and subject_kind is SubjectKind.KUNDE:
        raise ScoringModeViolationError(
            "Gemessene Hardening-Werte können keinem Kunden zugeordnet werden — "
            "nur das eigene System ist messbar (ADR-041 E2). Für Kunden gilt "
            "ausschließlich die manuelle Erfassung (Herkunft 'erfasst')."
        )
