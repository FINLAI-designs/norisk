"""
generate_report_use_case — Use Case: Kunden-Audit als PDF exportieren.

Orchestriert: Repository → CustomerReportGenerator → Pfad zurückgeben.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from core.exceptions import ValidationError
from core.logger import get_logger
from tools.customer_audit.application.risk_assessment_service import (
    RiskAssessmentService,
)
from tools.customer_audit.application.risk_matrix_export import render_risk_matrix_png
from tools.customer_audit.data.report_generator import CustomerReportGenerator
from tools.customer_audit.domain.entities import CustomerAuditResult
from tools.customer_audit.domain.repository import AuditRepository

log = get_logger(__name__)


class GenerateReportUseCase:
    """Generiert einen PDF-Report für ein Kunden-Audit.

    Attributes:
        _repository: Persistenz-Adapter zum Laden von Audits.
        _generator: PDF-Generator.
        _risk_service: Optionaler Risk-Service fuer Iter-2e-ii-PDF-Sektion.
            ``None`` blendet die Risk-Sektion stillschweigend aus —
            so bleibt der Report-Pfad fuer Pre-2e-Audits crash-frei.
    """

    def __init__(
        self,
        repository: AuditRepository,
        *,
        risk_service: RiskAssessmentService | None = None,
    ) -> None:
        """Initialisiert den Use Case.

        Args:
            repository: Repository-Adapter, implementiert das Port
:class:`AuditRepository` aus ``domain.repository``.
            risk_service: Optionaler:class:`RiskAssessmentService` —
                wenn vorhanden, wird die Risk-Liste pro audit_id geladen
                und in die PDF-Sektion eingeblendet (Iter 2e-ii).
        """
        self._repository = repository
        self._generator = CustomerReportGenerator()
        self._risk_service = risk_service

    def generate_for_id(
        self,
        audit_id: str,
        output_path: str | Path,
        *,
        hardening_score: float | None = None,
        hardening_herkunft: str = "",
    ) -> Path:
        """Lädt ein Audit und generiert den PDF-Report.

        Args:
            audit_id: UUID des Audits.
            output_path: Zieldateipfad (.pdf).
            hardening_score: Optionaler Scoring-Wert Phase D) für den
                kombinierten Kunden-Report; ``None`` blendet die Sektion aus.
            hardening_herkunft: Provenance des Scores (z.B. ``"erfasst"``).

        Returns:
            Pfad zur erzeugten PDF-Datei.

        Raises:
            ValueError: Wenn das Audit nicht gefunden wird.
            OSError: Bei Schreibfehlern.
        """
        result = self._repository.load_by_id(audit_id)
        if result is None:
            raise ValidationError(f"Audit nicht gefunden: {audit_id}")
        risks = self._load_risks(audit_id)
        if hardening_score is None:
            hardening_score, hardening_herkunft = self._fetch_hardening(
                result.subject_id
            )
        return self._generator.generate(
            result,
            output_path,
            risk_assessments=risks,
            risk_matrix_png=self._render_matrix(risks),
            hardening_score=hardening_score,
            hardening_herkunft=hardening_herkunft,
        )

    def generate_for_result(
        self,
        result: CustomerAuditResult,
        output_path: str | Path,
        *,
        hardening_score: float | None = None,
        hardening_herkunft: str = "",
    ) -> Path:
        """Generiert den PDF-Report direkt aus einem Result-Objekt.

        Args:
            result: Vollständiges CustomerAuditResult.
            output_path: Zieldateipfad (.pdf).
            hardening_score: Optionaler Scoring-Wert Phase D); ``None``
                blendet die Sektion aus.
            hardening_herkunft: Provenance des Scores (z.B. ``"erfasst"``).

        Returns:
            Pfad zur erzeugten PDF-Datei.

        Raises:
            OSError: Bei Schreibfehlern.
        """
        risks = self._load_risks(result.audit_id)
        if hardening_score is None:
            hardening_score, hardening_herkunft = self._fetch_hardening(
                result.subject_id
            )
        return self._generator.generate(
            result,
            output_path,
            risk_assessments=risks,
            risk_matrix_png=self._render_matrix(risks),
            hardening_score=hardening_score,
            hardening_herkunft=hardening_herkunft,
        )

    @staticmethod
    def _fetch_hardening(subject_id: str) -> tuple[float | None, str]:
        """Holt ``(Score, Herkunft)`` des Subjekts via core-Resolver (fail-soft).

 Phase D — kombinierter Audit+Scoring-PDF. KEIN direkter
        ``security_scoring``-Import: der Wert kommt über den lazy
        core-Port:func:`core.hardening_query.create_hardening_score_query`.
        """
        if not subject_id:
            return None, ""
        try:
            from core.hardening_query import (  # noqa: PLC0415
                create_hardening_score_query,
            )

            query = create_hardening_score_query()
            if query is None:
                return None, ""
            res = query.overall_by_subject(subject_id)
            return res if res is not None else (None, "")
        except Exception as exc:  # noqa: BLE001 — PDF-Pfad darf nie crashen
            log.warning(
                "Hardening-Score fuers PDF nicht ladbar: %s", type(exc).__name__
            )
            return None, ""

    @staticmethod
    def _render_matrix(risk_assessments: list | None) -> bytes | None:
        """Rendert die Risikomatrix als PNG (fail-soft; ``None`` ohne matplotlib/Risiken)."""
        if not risk_assessments:
            return None
        try:
            return render_risk_matrix_png(risk_assessments)
        except Exception as exc:  # noqa: BLE001 — PDF-Pfad darf nicht crashen
            log.warning("Risikomatrix-PNG fehlgeschlagen: %s", type(exc).__name__)
            return None

    def _load_risks(self, audit_id: str) -> list | None:
        """Laedt die Risk-Bewertungen, mit Fail-Silently-Semantik.

        Returns:
            Liste von:class:`RiskAssessment` oder ``None`` wenn der
            Service nicht injiziert ist oder das Laden fehlschlaegt.
        """
        if self._risk_service is None or not audit_id:
            return None
        try:
            return self._risk_service.load(audit_id)
        except Exception as exc:  # noqa: BLE001 — PDF-Pfad darf nicht crashen
            log.warning(
                "GenerateReport: Risk-Load fehlgeschlagen (%s)",
                type(exc).__name__,
            )
            return None
