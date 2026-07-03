"""
risk_assessment_service — UseCases fuer die BSI-200-3-Risiko-Matrix.

Iter 2e:
- ``initialize_defaults(audit_id)`` legt die 10 Default-Risiken an, falls
  noch keine Bewertungen fuer das Audit existieren.
- ``load(audit_id)`` liefert die aktuelle Risk-Liste.
- ``replace(audit_id, assessments)`` ersetzt sie atomar.
- ``summary(audit_id)`` aggregiert die Level-Verteilung fuer Reports.

Schichtzugehoerigkeit: application/ — darf domain + data + core importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass

from core.logger import get_logger
from tools.customer_audit.data.risk_assessment_repository import (
    DbRiskAssessmentRepository,
)
from tools.customer_audit.domain.risk_entities import (
    DEFAULT_RISK_CATALOG,
    RiskAssessment,
    RiskLevel,
)
from tools.customer_audit.domain.risk_repository import RiskAssessmentRepository

_log = get_logger(__name__)


@dataclass(frozen=True)
class RiskMatrixSummary:
    """Aggregat fuer Audit-Reports + UI-Banner.

    Attributes:
        total_count: Anzahl bewerteter Risiken (inkl. Customs).
        accepted_count: Anzahl explizit akzeptierter Risiken
                        (``is_accepted = True``).
        by_level: ``RiskLevel → count``.
        top_risks: Top-3 Risiken nach Score, sortiert desc.
    """

    total_count: int
    accepted_count: int
    by_level: dict[RiskLevel, int]
    top_risks: tuple[RiskAssessment, ...]


class RiskAssessmentService:
    """Anwendungs-Service fuer Risiko-Bewertungen."""

    def __init__(
        self, repository: RiskAssessmentRepository | None = None
    ) -> None:
        self._repo = repository or DbRiskAssessmentRepository()

    def initialize_defaults(self, audit_id: str) -> list[RiskAssessment]:
        """Legt 10 Default-Risiken an, wenn die Liste leer ist.

        Idempotent: zweite Aufrufe machen nichts.

        Returns:
            Die aktuelle Liste von Bewertungen (entweder die frisch
            angelegten Defaults, oder die bereits existierenden).
        """
        existing = self._repo.list_for_audit(audit_id)
        if existing:
            return existing
        defaults = [
            RiskAssessment(
                id=None,
                audit_id=audit_id,
                catalog_key=entry.key,
                probability=entry.default_probability,
                impact=entry.default_impact,
            )
            for entry in DEFAULT_RISK_CATALOG
        ]
        self._repo.upsert_for_audit(audit_id, defaults)
        return self._repo.list_for_audit(audit_id)

    def load(self, audit_id: str) -> list[RiskAssessment]:
        return self._repo.list_for_audit(audit_id)

    def replace(
        self, audit_id: str, assessments: list[RiskAssessment]
    ) -> None:
        self._repo.upsert_for_audit(audit_id, assessments)

    def delete_for_audit(self, audit_id: str) -> int:
        return self._repo.delete_for_audit(audit_id)

    def summary(self, audit_id: str) -> RiskMatrixSummary:
        assessments = self._repo.list_for_audit(audit_id)
        by_level: dict[RiskLevel, int] = {level: 0 for level in RiskLevel}
        accepted = 0
        for assessment in assessments:
            by_level[assessment.level] += 1
            if assessment.is_accepted:
                accepted += 1
        # Top-3 nach Score (prob*impact), sekundaer nach catalog_key fuer Stabilitaet.
        ranked = sorted(
            assessments,
            key=lambda a: (
                -(a.probability.value * a.impact.value),
                a.catalog_key or a.custom_title,
            ),
        )
        return RiskMatrixSummary(
            total_count=len(assessments),
            accepted_count=accepted,
            by_level=by_level,
            top_risks=tuple(ranked[:3]),
        )
