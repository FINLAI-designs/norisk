"""
cve_exposure_service — Aggregiert CVE-/KEV-/CSAF-Signale zur Exposure-Kennzahl.

Nutzt ausschließlich den injizierten ``CveExposureRepository`` — kein direkter
Netzwerk-I/O, keine neuen NVD- oder CSAF-Feed-Requests. Fehlen gecachte
Daten (leerer CVE-Cache und keine Advisory-Matches), wird
``CveExposureData.score = None`` zurückgegeben — kein künstlicher 0- oder
100-Wert.

Schichtzugehörigkeit: application/ — keine GUI-Imports, kein direkter DB-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from tools.security_scoring.domain.cve_exposure import (
    CVSS_CRITICAL,
    CVSS_HIGH,
    CVSS_MEDIUM,
    CveExposureData,
    berechne_exposure_score,
    status_from_score,
)

log = get_logger(__name__)


class CveExposureService:
    """Application-Service für den CVE-Exposure-Teilwert des Security-Scores.

    Attributes:
        _repository: CveExposureRepository-Instanz.
    """

    def __init__(self, repository=None) -> None:
        """Initialisiert den Service mit einem Repository.

        Fehlt ``repository``, wird eine Standard-Instanz konstruiert
        (baut CacheRepository, AdvisoryRepository, TechStackRepository
        mit Default-Konstruktoren).

        Args:
            repository: CveExposureRepository oder None (Standard).
        """
        if repository is None:
            from tools.security_scoring.data.cve_exposure_repository import (  # noqa: PLC0415
                CveExposureRepository,
            )

            repository = CveExposureRepository()
        self._repository = repository

    def get_current_exposure(self) -> CveExposureData:
        """Aggregiert die aktuellen Exposure-Kennzahlen.

        Ruft ausschließlich lesende Methoden auf dem Repository auf.
        Bei Fehlern wird "Keine Daten" zurückgegeben, damit das Scoring
        nicht abstürzt.

        Returns:
            CveExposureData. ``score=None`` wenn weder CVEs noch
            Advisory-Matches verfügbar sind.
        """
        try:
            cves = self._repository.lade_techstack_cves()
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning(
                "Techstack-CVE-Aggregation fehlgeschlagen: %s", type(exc).__name__
            )
            cves = []

        try:
            advisory_count = self._repository.zaehle_betroffene_advisories()
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning(
                "CSAF-Advisory-Aggregation fehlgeschlagen: %s", type(exc).__name__
            )
            advisory_count = 0

        try:
            last_updated = self._repository.letzte_aktualisierung()
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning(
                "Aktualisierungs-Zeitstempel fehlgeschlagen: %s", type(exc).__name__
            )
            last_updated = ""

        if not cves and advisory_count == 0:
            return CveExposureData(
                total_cves=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                kev_count=0,
                affected_advisories=0,
                score=None,
                status=status_from_score(None),
                last_updated="",
            )

        critical_count = 0
        high_count = 0
        medium_count = 0
        kev_count = 0
        for cve in cves:
            cvss = float(getattr(cve, "cvss_score", 0.0) or 0.0)
            if cvss >= CVSS_CRITICAL:
                critical_count += 1
            elif cvss >= CVSS_HIGH:
                high_count += 1
            elif cvss >= CVSS_MEDIUM:
                medium_count += 1
            if getattr(cve, "cisa_kev", False):
                kev_count += 1

        score = berechne_exposure_score(
            critical=critical_count,
            high=high_count,
            medium=medium_count,
            kev=kev_count,
            advisories=advisory_count,
        )
        return CveExposureData(
            total_cves=len(cves),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            kev_count=kev_count,
            affected_advisories=advisory_count,
            score=score,
            status=status_from_score(score),
            last_updated=last_updated,
        )
