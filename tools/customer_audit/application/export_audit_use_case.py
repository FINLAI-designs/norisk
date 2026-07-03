"""
export_audit_use_case — Use Case: Audit als JSON/PDF exportieren.

Vorbereitung für den PDF-Export (Prompt 4).
Aktuell: JSON-Export + strukturierte Textausgabe.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from pathlib import Path

from core.logger import get_logger
from tools.customer_audit.domain.entities import CustomerAuditResult

log = get_logger(__name__)


class ExportAuditUseCase:
    """Exportiert ein Audit-Ergebnis in verschiedene Formate.

    Bereitet die Daten für den PDF-Generator (Prompt 4) auf.
    """

    def export_json(
        self,
        result: CustomerAuditResult,
        target_path: Path,
    ) -> Path:
        """Exportiert das Ergebnis als JSON-Datei.

        Args:
            result: Zu exportierendes Ergebnis.
            target_path: Zieldatei-Pfad.

        Returns:
            Pfad der gespeicherten Datei.

        Raises:
            OSError: Bei Schreibfehlern.
        """
        data = result.to_dict()
        target_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info("Audit exportiert: %s", target_path)
        return target_path

    def build_report_data(self, result: CustomerAuditResult) -> dict:
        """Bereitet strukturierte Daten für den PDF-Report vor.

        Gibt ein Dict zurück, das der PDF-Generator (Prompt 4) direkt
        verarbeiten kann.

        Args:
            result: Kunden-Audit-Ergebnis.

        Returns:
            Report-Daten-Dict mit allen Sektionen.
        """
        return {
            "type": "customer_audit",
            "report_title": "Kunden Security Audit",
            "subtitle": "NoRisk by FINLAI",
            "company": result.customer_data.firmenname,
            "contact": result.customer_data.ansprechpartner_name,
            "date": result.created_at,
            "overall_score": result.overall_score,
            "risk_level": result.risk_level,
            "category_scores": [s.to_dict() for s in result.category_scores],
            "recommendations": result.recommendations,
            "details": {
                "customer": result.customer_data.to_dict(),
                "infrastructure": result.infrastructure_data.to_dict(),
                "organizational": result.organizational_data.to_dict(),
                "network": result.network_data.to_dict(),
            },
        }
