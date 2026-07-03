"""
risk_repository — Port (Interface) fuer Risk-Persistenz.

Iter 2e: Hex-Architecture-konformer Port. Konkrete
SQLCipher-Implementation liegt in ``data/risk_assessment_repository.py``.

Schichtzugehoerigkeit: domain/ — keine Imports aus aeusseren Schichten.
"""

from __future__ import annotations

from typing import Protocol

from tools.customer_audit.domain.risk_entities import RiskAssessment


class RiskAssessmentRepository(Protocol):
    """Persistenz-Port fuer Risiko-Bewertungen pro Audit."""

    def upsert_for_audit(
        self, audit_id: str, assessments: list[RiskAssessment]
    ) -> None:
        """Ersetzt die komplette Risk-Liste eines Audits atomar."""
        ...

    def list_for_audit(self, audit_id: str) -> list[RiskAssessment]:
        """Liefert die Risk-Bewertungen eines Audits (sortiert nach
        score desc, dann title asc)."""
        ...

    def delete_for_audit(self, audit_id: str) -> int:
        """Loescht alle Bewertungen eines Audits. Liefert Anzahl
        geloeschter Zeilen."""
        ...
