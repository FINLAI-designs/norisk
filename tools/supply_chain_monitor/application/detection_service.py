"""
detection_service — Orchestrator fuer die drei Detection-Quellen.

Iteration 2b:

- ``run_detection(domains)`` startet alle drei:class:`detectors`-Implementierungen
  und persistiert die Ergebnisse via Upsert.
- ``list_suggestions`` aggregiert die persistierten Treffer zu
:class:`VendorSuggestion` (gewichteter Confidence-Score).
- ``accept_suggestion`` / ``reject_suggestion`` / ``defer_suggestion``
  steuern den Status-Lifecycle.

Schichtzugehoerigkeit: application/ — darf domain + data + andere
application-Module + core importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from core.logger import get_logger
from tools.supply_chain_monitor.application.detectors import (
    CertIssuerDetector,
    InstalledAppsDetector,
    MxLookupDetector,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.data.vendor_catalog_repository import (
    VendorCatalogRepository,
)
from tools.supply_chain_monitor.data.vendor_detection_repository import (
    VendorDetectionRepository,
)
from tools.supply_chain_monitor.domain.models import (
    DetectionStatus,
    Vendor,
    VendorCatalogEntry,
    VendorDetection,
    VendorSuggestion,
)

_log = get_logger(__name__)

_DEFAULT_NEW_VENDOR_CRITICALITY: int = 3


@dataclass(frozen=True)
class DetectionRunSummary:
    """Resultat eines:meth:`DetectionService.run_detection`-Aufrufs."""

    started_at: datetime
    finished_at: datetime
    installed_apps_count: int
    mx_lookup_count: int
    cert_issuer_count: int

    @property
    def total_count(self) -> int:
        return self.installed_apps_count + self.mx_lookup_count + self.cert_issuer_count


class DetectionService:
    """Service-Layer fuer die Auto-Detection-Pipeline."""

    def __init__(
        self,
        *,
        catalog_repository: VendorCatalogRepository | None = None,
        detection_repository: VendorDetectionRepository | None = None,
        vendor_service: VendorService | None = None,
        installed_apps_detector: InstalledAppsDetector | None = None,
        mx_lookup_detector: MxLookupDetector | None = None,
        cert_issuer_detector: CertIssuerDetector | None = None,
    ) -> None:
        self._catalog_repo = catalog_repository or VendorCatalogRepository()
        self._detection_repo = detection_repository or VendorDetectionRepository()
        self._vendor_service = vendor_service or VendorService()
        self._installed = installed_apps_detector or InstalledAppsDetector()
        self._mx = mx_lookup_detector or MxLookupDetector()
        self._cert = cert_issuer_detector or CertIssuerDetector()

    # ------------------------------------------------------------------
    # Detection-Run
    # ------------------------------------------------------------------

    def run_detection(self, domains: Iterable[str]) -> DetectionRunSummary:
        """Fuehrt alle drei Quellen aus und persistiert die Treffer.

        Args:
            domains: Liste von Domains fuer MX- und Cert-Scans. Kann leer
                sein — dann laeuft nur die Installed-Apps-Detection.

        Returns:
:class:`DetectionRunSummary` mit Counts pro Quelle.
        """
        started = datetime.now(UTC)
        catalog = self._catalog_repo.list_all()
        domain_list = [d for d in domains if d and d.strip()]

        installed = self._installed.detect(catalog)
        mx = self._mx.detect(catalog, domain_list)
        cert = self._cert.detect(catalog, domain_list)

        for det in (*installed, *mx, *cert):
            self._detection_repo.upsert(det)

        finished = datetime.now(UTC)
        summary = DetectionRunSummary(
            started_at=started,
            finished_at=finished,
            installed_apps_count=len(installed),
            mx_lookup_count=len(mx),
            cert_issuer_count=len(cert),
        )
        _log.info(
            "detection_run installed=%s mx=%s cert=%s duration_ms=%s",
            summary.installed_apps_count,
            summary.mx_lookup_count,
            summary.cert_issuer_count,
            int((summary.finished_at - summary.started_at).total_seconds() * 1000),
        )
        return summary

    # ------------------------------------------------------------------
    # Suggestions-Aggregation
    # ------------------------------------------------------------------

    def list_suggestions(self) -> list[VendorSuggestion]:
        """Aggregiert die actionable Detections zu:class:`VendorSuggestion`.

        Aggregations-Regel:
        - Pro Catalog-Eintrag werden ALLE Detections geladen (auch
          ACCEPTED/REJECTED — der Aggregator filtert).
        - Punkte zaehlen die **unique** Quellen mit PENDING- oder
          DEFERRED-Detections (REJECTED/ACCEPTED beeinflussen die
          Aggregation nicht).
        - Catalog-Eintraege ohne actionable Detections werden NICHT
          als Suggestion geliefert.

        Sortierung: Confidence desc (HIGH zuerst), dann Punkte desc,
        dann ``last_detected_at`` desc.
        """
        actionable = self._detection_repo.list_actionable()
        if not actionable:
            return []

        # Wir brauchen pro Eintrag ALLE Detections (nicht nur actionable),
        # damit ``VendorSuggestion.detections`` die volle Historie zeigt.
        by_catalog: dict[int, list[VendorDetection]] = {}
        for det in actionable:
            by_catalog.setdefault(det.catalog_entry_id, []).append(det)

        suggestions: list[VendorSuggestion] = []
        for catalog_id, dets in by_catalog.items():
            entry = self._catalog_repo.get_by_id(catalog_id)
            if entry is None:
                # Catalog-Eintrag wurde geloescht waehrend Detections noch
                # existieren — Detections sind verwaist, ueberspringen.
                _log.warning(
                    "list_suggestions: verwaiste Detections fuer catalog_entry_id=%s",
                    catalog_id,
                )
                continue
            all_dets = tuple(self._detection_repo.list_for_catalog_entry(catalog_id))
            suggestions.append(VendorSuggestion.from_detections(entry, all_dets))

        suggestions.sort(
            key=lambda s: (
                -_confidence_rank(s.confidence),
                -s.source_points,
                -s.last_detected_at.timestamp(),
            )
        )
        return suggestions

    def list_catalog_entries(self) -> list[VendorCatalogEntry]:
        """Pass-through fuer GUI/Catalog-Management."""
        return self._catalog_repo.list_all()

    # ------------------------------------------------------------------
    # User-Entscheidungen
    # ------------------------------------------------------------------

    def accept_suggestion(
        self,
        catalog_entry_id: int,
        *,
        criticality_score: int = _DEFAULT_NEW_VENDOR_CRITICALITY,
        notes: str = "",
    ) -> Vendor:
        """Uebernimmt eine Suggestion als neuen Vendor.

        Erzeugt einen:class:`Vendor` aus dem Catalog-Eintrag (canonical_name +
        default_category) und markiert ALLE PENDING/DEFERRED-Detections
        des Eintrags als ``ACCEPTED`` (verknuepft mit der Vendor-ID).
        Bereits REJECTED-Detections bleiben unangetastet.

        Args:
            catalog_entry_id: ID des Catalog-Eintrags.
            criticality_score: Initialer Kritikalitaets-Score (1-5, default 3).
            notes: Optionale Notiz auf dem neuen Vendor.

        Returns:
            Der neue:class:`Vendor`.

        Raises:
            ValueError: Wenn der Catalog-Eintrag nicht existiert oder kein
                Vendor angelegt werden kann (Domain-Validierung).
        """
        entry = self._catalog_repo.get_by_id(catalog_entry_id)
        if entry is None:
            raise ValueError(f"Kein Catalog-Eintrag mit id={catalog_entry_id}.")
        composed_notes = notes or _format_catalog_notes(entry)
        vendor = self._vendor_service.add_vendor(
            name=entry.canonical_name,
            category=entry.default_category,
            criticality_score=criticality_score,
            notes=composed_notes,
        )
        for det in self._detection_repo.list_for_catalog_entry(catalog_entry_id):
            if det.id is None or not det.is_actionable():
                continue
            self._detection_repo.set_status(
                det.id,
                DetectionStatus.ACCEPTED,
                vendor_id=vendor.id,
            )
        return vendor

    def reject_suggestion(self, catalog_entry_id: int) -> int:
        """Markiert alle actionable Detections des Catalog-Eintrags als REJECTED.

        Returns:
            Anzahl betroffener Detections.
        """
        return self._set_status_for_actionable(
            catalog_entry_id, DetectionStatus.REJECTED
        )

    def defer_suggestion(self, catalog_entry_id: int) -> int:
        """Markiert alle PENDING-Detections des Catalog-Eintrags als DEFERRED.

        Returns:
            Anzahl betroffener Detections.
        """
        affected = 0
        for det in self._detection_repo.list_for_catalog_entry(catalog_entry_id):
            if det.id is None:
                continue
            if det.status is DetectionStatus.PENDING:
                self._detection_repo.set_status(det.id, DetectionStatus.DEFERRED)
                affected += 1
        return affected

    def _set_status_for_actionable(
        self,
        catalog_entry_id: int,
        new_status: DetectionStatus,
    ) -> int:
        affected = 0
        for det in self._detection_repo.list_for_catalog_entry(catalog_entry_id):
            if det.id is None or not det.is_actionable():
                continue
            self._detection_repo.set_status(det.id, new_status)
            affected += 1
        return affected


def _confidence_rank(confidence) -> int:  # noqa: ANN001 — DetectionConfidence enum
    from tools.supply_chain_monitor.domain.models import (  # noqa: PLC0415
        DetectionConfidence,
    )

    return {
        DetectionConfidence.HIGH: 3,
        DetectionConfidence.MEDIUM: 2,
        DetectionConfidence.LOW: 1,
    }[confidence]


def _format_catalog_notes(entry: VendorCatalogEntry) -> str:
    if entry.notes:
        return f"Aus Auto-Detection uebernommen. {entry.notes}"
    return "Aus Auto-Detection uebernommen."
