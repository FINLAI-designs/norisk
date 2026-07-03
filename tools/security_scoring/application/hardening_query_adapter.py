"""hardening_query_adapter — Implementiert core.hardening_query.HardeningScoreQuery Phase D).

Stellt den jüngsten Hardening-Score eines Subjekts (Score + Provenance) für den
kombinierten Kunden-PDF bereit. Wird ausschließlich über den lazy core-Resolver
:func:`core.hardening_query.create_hardening_score_query` bezogen — kein direkter
``customer_audit → security_scoring``-Import.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.security_scoring.application.scoring_service import ScoringService


class ScoringHardeningQuery:
    """``HardeningScoreQuery``-Implementierung auf Basis des ``ScoringService``."""

    def overall_by_subject(self, subject_id: str) -> tuple[float, str] | None:
        """Jüngster Hardening-Score eines Subjekts als ``(score, herkunft)``.

        Args:
            subject_id: UUID des Subjekts.

        Returns:
            ``(overall_score, herkunft.value)`` oder ``None`` (kein Score / leeres
            ``subject_id`` / fail-soft).
        """
        if not subject_id:
            return None
        result = ScoringService().lade_letztes_hardening_result_by_subject(subject_id)
        if result is None:
            return None
        return float(result.overall_score), result.herkunft.value


def create_default_hardening_score_query() -> ScoringHardeningQuery:
    """Factory für den lazy core-Resolver."""
    return ScoringHardeningQuery()
