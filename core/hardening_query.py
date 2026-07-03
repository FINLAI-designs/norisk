"""core.hardening_query — Lazy-Resolver für den Hardening-Score eines Subjekts Phase D).

Erlaubt ``customer_audit``, den Scoring-(Hardening-)Wert eines Subjekts für den
kombinierten Kunden-PDF (Audit + Scoring in EINEM Dokument) zu lesen, OHNE
``security_scoring`` direkt zu importieren / Contract 4c).
``customer_audit`` importiert ausschließlich diesen core-Resolver (tools→core,
import-linter-konform); der eine bewusste Lazy ``core → security_scoring``-Import
ist in der import-linter-Baseline (Contract 5 ``ignore_imports``) hinterlegt —
exakt wie:mod:`core.security_subject.resolver`.

Fail-soft nach Hausmuster: ist die Implementierung nicht ladbar, liefert der
Resolver ``None`` statt zu werfen (PDF wird dann ohne Scoring-Block erzeugt).

Schichtzugehörigkeit: core/ — der ``tools``-Import läuft bewusst **lazy**
innerhalb der Funktion (keine statische ``core → tools``-Kante).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.logger import get_logger

log = get_logger(__name__)


@runtime_checkable
class HardeningScoreQuery(Protocol):
    """Vertrag: jüngster Hardening-Score eines Subjekts (Score + Herkunft)."""

    def overall_by_subject(self, subject_id: str) -> tuple[float, str] | None:
        """Liefert ``(overall_score, herkunft)`` oder ``None``.

        Args:
            subject_id: UUID des Subjekts.

        Returns:
            Tuple aus Gesamt-Score (0–100) und Herkunft-Wert (z.B. ``"erfasst"``/
            ``"gemessen"``), oder ``None`` wenn kein Hardening-Score vorliegt.
        """
        ...


def create_hardening_score_query() -> HardeningScoreQuery | None:
    """Liefert die konkrete (security_scoring-)Implementierung (fail-soft).

    Returns:
        Einsatzbereite Query oder ``None``, wenn die Implementierung nicht ladbar
        bzw. das Repository nicht initialisierbar ist (fail-soft beim Aufrufer).
    """
    try:
        # Lazy import: hält core frei von einer statischen tools-Abhängigkeit.
        from tools.security_scoring.application.hardening_query_adapter import (  # noqa: PLC0415
            create_default_hardening_score_query,
        )

        return create_default_hardening_score_query()
    except Exception as exc:  # noqa: BLE001 — fail-soft Cross-Tool-Resolver-Grenze
        log.warning(
            "HardeningScoreQuery nicht verfuegbar (%s) — Scoring-Block im PDF "
            "deaktiviert.",
            type(exc).__name__,
        )
        return None
