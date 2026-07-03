"""
org_security_service — Orchestriert das Organisations-Sicherheits-Assessment.

Verbindet Auto-Detection (Windows Hello, Passwort-Manager-Installationen),
Self-Assessment-Speicherung und Score-Komponenten-Berechnung.

Schichtzugehörigkeit: application/ — keine GUI-Imports, kein direktes DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from core.logger import get_logger
from tools.security_scoring.application.os_detection_service import (
    STATUS_AKTIV,
    STATUS_INAKTIV,
)
from tools.security_scoring.domain.models import ScoreComponent
from tools.security_scoring.domain.org_security import (
    DEFAULT_ORG_WEIGHTS,
    FRAGEN_DSGVO,
    FRAGEN_MFA,
    FRAGEN_PASSWORT_MANAGER,
    FRAGEN_PHISHING,
    METRIK_ANZEIGENAME,
    METRIK_DSGVO,
    METRIK_MFA,
    METRIK_PASSWORT_MANAGER,
    METRIK_PHISHING,
    MFA_AUTO_KEY,
    PM_AUTO_KEY,
    OrgAntwort,
    OrgAssessment,
    OrgMetrikErgebnis,
)
from tools.security_scoring.domain.scoring_engine import (
    calculate_self_assessment_score,
)

log = get_logger(__name__)

_METRIK_ZU_FRAGEN: dict[str, tuple] = {
    METRIK_DSGVO: FRAGEN_DSGVO,
    METRIK_PHISHING: FRAGEN_PHISHING,
    METRIK_MFA: FRAGEN_MFA,
    METRIK_PASSWORT_MANAGER: FRAGEN_PASSWORT_MANAGER,
}

_METRIK_HAT_AUTO: dict[str, str] = {
    METRIK_MFA: MFA_AUTO_KEY,
    METRIK_PASSWORT_MANAGER: PM_AUTO_KEY,
}


class OrgSecurityService:
    """Application-Service für das Org-Security-Assessment.

    Args:
        repository: Repository-Instanz (OrgAssessmentRepository-Protokoll).
    """

    def __init__(self, repository) -> None:  # noqa: ANN001 — Duck-typed protocol
        """Initialisiert den Service.

        Args:
            repository: Repository mit ``speichere`` und ``lade_letztes``.
        """
        self._repo = repository

    # ------------------------------------------------------------------
    # Persistenz
    # ------------------------------------------------------------------

    def speichere_assessment(
        self,
        dsgvo: OrgMetrikErgebnis,
        phishing: OrgMetrikErgebnis,
        mfa: OrgMetrikErgebnis,
        passwort_manager: OrgMetrikErgebnis,
    ) -> OrgAssessment:
        """Persistiert ein Assessment und gibt es zurück.

        Args:
            dsgvo: Ergebnis der DSGVO-Metrik.
            phishing: Ergebnis der Phishing-Metrik.
            mfa: Ergebnis der MFA-Metrik.
            passwort_manager: Ergebnis der Passwort-Manager-Metrik.

        Returns:
            Das gespeicherte OrgAssessment.
        """
        assessment = OrgAssessment(
            audit_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            dsgvo=dsgvo,
            phishing=phishing,
            mfa=mfa,
            passwort_manager=passwort_manager,
        )
        self._repo.speichere(assessment)
        return assessment

    def lade_letztes(self) -> OrgAssessment | None:
        """Gibt das zuletzt gespeicherte Assessment zurück oder None."""
        try:
            return self._repo.lade_letztes()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Laden des Org-Assessments fehlgeschlagen: %s", type(exc).__name__
            )
            return None

    def lade_letztes_by_subject(self, subject_id: str) -> OrgAssessment | None:
        """Juengstes Org-Assessment eines Subjekts F-5, fail-soft).

        Subjekt-gefilterter Lese-Pfad gegen Cross-Subjekt-Leaks (IDOR) in
        Multi-Subjekt-Kontexten. Faellt fail-soft auf ``None`` zurueck.
        """
        try:
            return self._repo.lade_letztes_by_subject(subject_id)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Laden des Org-Assessments (Subjekt) fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return None

    # ------------------------------------------------------------------
    # Score-Komponenten
    # ------------------------------------------------------------------

    def baue_komponenten(
        self, assessment: OrgAssessment | None
    ) -> list[ScoreComponent]:
        """Erstellt ScoreComponents für die Org-Metriken.

        Leere Liste, wenn kein Assessment vorliegt. Metriken, deren Fragen
        komplett „nicht anwendbar" sind, werden ganz weggelassen
        (``_komponente_fuer`` liefert ``None``) — so fallen sie aus der
        Org-Block-Gewichtung, statt den Gesamtscore über den Coverage-Cap zu
        senken (das wäre ``data_available=False``, die Semantik für FEHLENDE
        Daten). ``calculate_overall_score`` normalisiert die Gewichte.

        Args:
            assessment: Letztes gespeichertes Assessment oder None.

        Returns:
            Liste mit bis zu vier ScoreComponents (N/A-Metriken ausgelassen).
        """
        if assessment is None:
            return []

        metriken = assessment.metriken()
        komponenten = [self._komponente_fuer(m) for m in metriken]
        weggelassen = [
            m.metrik
            for m, k in zip(metriken, komponenten, strict=True)
            if k is None
        ]
        if weggelassen:
            # Observability: eine ganze Bewertungsdimension faellt auf
            # Nutzerwunsch (komplett N/A) aus dem Score — nur Metrik-Keys,
            # kein PII (erklaert spaetere Score-Spruenge-Review-P3).
            log.info(
                "Org-Metriken komplett n/a, aus dem Score ausgelassen: %s",
                weggelassen,
            )
        return [k for k in komponenten if k is not None]

    @staticmethod
    def _komponente_fuer(
        ergebnis: OrgMetrikErgebnis,
    ) -> ScoreComponent | None:
        """Baut eine ScoreComponent für eine einzelne Metrik.

        ``NICHT_ANWENDBAR``-Antworten fallen aus dem Nenner (Microsoft-
        Secure-Score-Stil); ``UNBEKANNT``/``NEIN`` bleiben drin (unverifiziert =
        kein Kredit). Die Auto-Detection zählt als Zusatz-Frage — Status
        ``unbekannt`` (kein Detektions-Signal) penalisiert aber nicht und fällt
        ebenfalls aus dem Nenner. Sind ALLE Fragen einer Metrik N/A, ist die
        Metrik nicht bewertbar → ``None`` (sie fällt aus dem Org-Block).

        Args:
            ergebnis: Antworten + Auto-Status einer Metrik.

        Returns:
            ScoreComponent, oder ``None`` wenn die Metrik komplett N/A ist.
        """
        fragen = _METRIK_ZU_FRAGEN[ergebnis.metrik]
        antworten = {
            f.key: ergebnis.antworten.get(f.key, OrgAntwort.UNBEKANNT)
            for f in fragen
        }
        antwortbar = [
            key for key, a in antworten.items() if a != OrgAntwort.NICHT_ANWENDBAR
        ]
        anzahl_gesamt = len(antwortbar)
        anzahl_ja = sum(1 for key in antwortbar if antworten[key] == OrgAntwort.JA)

        # Auto-Detection als Zusatz-Frage. ``unbekannt`` ohne Override = kein
        # Signal → aus dem Nenner (nicht penalisieren). Ein eigener PM-Name
        # zählt als definitiv erfüllt, auch ohne Auto-Treffer.
        auto_key = _METRIK_HAT_AUTO.get(ergebnis.metrik)
        if auto_key:
            custom_override = bool(
                ergebnis.custom_pm_name.strip()
                and ergebnis.metrik == METRIK_PASSWORT_MANAGER
            )
            if (
                ergebnis.auto_status in (STATUS_AKTIV, STATUS_INAKTIV)
                or custom_override
            ):
                anzahl_gesamt += 1
                if ergebnis.auto_status == STATUS_AKTIV or custom_override:
                    anzahl_ja += 1

        if anzahl_gesamt == 0:
            # Metrik komplett „nicht anwendbar" → nicht bewertbar.
            return None

        score = calculate_self_assessment_score(anzahl_ja, anzahl_gesamt)
        return ScoreComponent(
            name=METRIK_ANZEIGENAME[ergebnis.metrik],
            score=score,
            weight=DEFAULT_ORG_WEIGHTS[ergebnis.metrik],
            findings_critical=0,
            findings_high=max(0, anzahl_gesamt - anzahl_ja),
            findings_medium=0,
            source_tool="org_security",
        )

    # ------------------------------------------------------------------
    # Hilfsmethoden
    # ------------------------------------------------------------------

    @staticmethod
    def anzahl_kriterien(metrik: str) -> int:
        """Gibt die Gesamtanzahl Kriterien einer Metrik (inkl. Auto-Feld).

        Args:
            metrik: Metrik-Key.

        Returns:
            Anzahl Kriterien (Self-Assessment + optional Auto-Feld).
        """
        anzahl = len(_METRIK_ZU_FRAGEN.get(metrik, ()))
        if metrik in _METRIK_HAT_AUTO:
            anzahl += 1
        return anzahl
