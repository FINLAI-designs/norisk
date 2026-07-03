"""
compliance_assessor — Bewertet Supply-Chain-Daten gegen Compliance-Frameworks.

Iter 2d-ii-ii, 2026-05-15): Pro:class:`ComplianceFramework` ein
Catalog von:class:`ComplianceRequirement`-Eintraegen plus eine
Heuristik-Funktion, die das aktuelle Daten-Bild (Vendoren, AVVs,
Subprocessors, Detections, Off-Boardings) auf
:class:`ComplianceCoverage`-Stufen abbildet.

Anforderungen, die rein procedural sind (Strategie, Rollen, Schulung)
werden als ``MANUAL_REVIEW`` markiert — der Tool-Daten-Layer kann sie
nicht automatisch bewerten. Der PDF-Report blendet sie trotzdem ein,
damit der Compliance-Verantwortliche eine Vollstaendigkeitsmatrix hat.

Schichtzugehoerigkeit: application/ — darf domain + data + andere
application-Module + core importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1-ii, 2026-05-15)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from core.logger import get_logger
from tools.supply_chain_monitor.application.avv_service import AvvService
from tools.supply_chain_monitor.application.subprocessor_service import (
    SubprocessorService,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.data.vendor_detection_repository import (
    VendorDetectionRepository,
)
from tools.supply_chain_monitor.domain.models import (
    AvvDocumentStatus,
    ComplianceAssessment,
    ComplianceCoverage,
    ComplianceFramework,
    ComplianceRequirement,
    VendorCategory,
)

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Catalog der bekannten Anforderungen
# ---------------------------------------------------------------------------

_NIST_GVSC: Final[list[ComplianceRequirement]] = [
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-01",
        title="Supply-Chain-Risk-Management-Strategie etabliert",
        description=(
            "Eine kommunizierte Strategie fuer Supply-Chain-Risiken existiert "
            "und ist mit Stakeholdern abgestimmt."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-02",
        title="Rollen und Verantwortlichkeiten festgelegt",
        description=(
            "Rollen fuer Supply-Chain-Risk-Management sind festgelegt, "
            "kommuniziert und mit Ressourcen ausgestattet."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-03",
        title="In Cyber- und Unternehmens-Risiko-Mgmt integriert",
        description=(
            "Supply-Chain-Risk-Management ist in das uebergeordnete "
            "Cybersecurity- und Unternehmens-Risikomanagement integriert."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-04",
        title="Lieferanten bekannt und nach Kritikalitaet priorisiert",
        description=(
            "Alle relevanten Lieferanten sind erfasst und mit einer "
            "Kritikalitaets-Bewertung versehen."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-05",
        title="Anforderungen an Lieferanten vertraglich festgelegt",
        description=(
            "Cybersecurity- und Datenschutzanforderungen werden mit "
            "Lieferanten in Vertraegen verbindlich vereinbart (AVV nach "
            "DSGVO Art. 28)."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-06",
        title="Due-Diligence vor Vertragsabschluss",
        description=(
            "Vor und waehrend Geschaeftsbeziehungen wird Due-Diligence "
            "auf Lieferanten durchgefuehrt (z. B. Auto-Detection, MX-Lookup, "
            "Cert-Issuer-Pruefung)."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-07",
        title="Risiken pro Lieferant verstanden",
        description=(
            "Risiken jedes Lieferanten und seiner Sub-Lieferanten sind "
            "dokumentiert (Art-28-Checkliste, Subprocessor-Liste, "
            "Konzentrationsrisiko)."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-08",
        title="Lieferanten-Praktiken in laufendes Risk-Mgmt integriert",
        description=(
            "Cybersecurity-Praktiken der Lieferanten fliessen ins laufende "
            "Risikomanagement ein."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-09",
        title="Performance der Lieferanten ueberwacht",
        description=(
            "Performance und Compliance der Lieferanten werden regelmaessig "
            "ueberwacht und ausgewertet."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.NIST_CSF_GVSC,
        identifier="GV.SC-10",
        title="Plaene fuer Beendigung der Lieferanten-Beziehung",
        description=(
            "Plaene fuer das Ende der Lieferanten-Beziehung sind "
            "dokumentiert (Off-Boarding-Checkliste, Daten-Loeschung, "
            "Account-Stilllegung)."
        ),
    ),
]


_BSI_OPS_2_3: Final[list[ComplianceRequirement]] = [
    ComplianceRequirement(
        framework=ComplianceFramework.BSI_OPS_2_3,
        identifier="OPS.2.3.A2",
        title="Cloud-Strategie erstellt",
        description=(
            "Eine schriftliche Cloud-Strategie liegt vor und ist auf die "
            "Risiken der Kanzlei abgestimmt."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.BSI_OPS_2_3,
        identifier="OPS.2.3.A4",
        title="Vertragsgestaltung mit Cloud-Anbietern",
        description=(
            "Vertraege mit Cloud-Anbietern enthalten alle erforderlichen "
            "Pflichtinhalte (AVV nach DSGVO Art. 28, Service-Levels, "
            "Audit-Rechte)."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.BSI_OPS_2_3,
        identifier="OPS.2.3.A6",
        title="Anforderungs- und Service-Definitions-Dokument",
        description=(
            "Anforderungen und Service-Definitionen sind pro Cloud-Anbieter "
            "schriftlich festgehalten."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.BSI_OPS_2_3,
        identifier="OPS.2.3.A10",
        title="Cloud-Exit-Strategie erstellt",
        description=(
            "Eine Exit-Strategie inklusive Daten-Rueckgabe und Loeschnachweis "
            "ist je Cloud-Anbieter vorhanden (Off-Boarding-Checkliste)."
        ),
    ),
]


_BSI_ORP_5: Final[list[ComplianceRequirement]] = [
    ComplianceRequirement(
        framework=ComplianceFramework.BSI_ORP_5,
        identifier="ORP.5.A6",
        title="Verpflichtung externer Mitarbeiter auf Regelungen",
        description=(
            "Externe Mitarbeiter (z. B. IT-Dienstleister) werden auf die "
            "geltenden Sicherheitsregelungen schriftlich verpflichtet."
        ),
    ),
    ComplianceRequirement(
        framework=ComplianceFramework.BSI_ORP_5,
        identifier="ORP.5.A7",
        title="Bewertung externer Lieferanten",
        description=(
            "Externe Lieferanten und Subprocessors werden vor Vertragsbeginn "
            "und periodisch sicherheitsmaessig bewertet."
        ),
    ),
]


COMPLIANCE_REQUIREMENTS: Final[list[ComplianceRequirement]] = (
    [*_NIST_GVSC, *_BSI_OPS_2_3, *_BSI_ORP_5]
)


# ---------------------------------------------------------------------------
# Aggregierte Snapshot-Daten
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DataSnapshot:
    """In-Memory-Snapshot aller Daten, die der Assessor braucht.

    Wird einmal pro:meth:`ComplianceAssessor.assess_all` aufgebaut —
    spart pro Anforderung den DB-Roundtrip.
    """

    vendor_count: int
    critical_vendor_count: int  # criticality_score >= 4
    cloud_vendor_count: int  # category in {CLOUD}
    vendors_with_active_avv: set[int]
    vendors_with_complete_checklist: set[int]
    total_avvs: int
    active_avvs: int
    expired_avvs: int
    overdue_avvs: int
    subprocessor_count: int
    concentrated_subprocessor_count: int
    actionable_detection_count: int
    has_any_detection: bool
    offboarding_count: int
    completed_offboarding_count: int


# ---------------------------------------------------------------------------
# Assessor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ComplianceReport:
    """Aggregat aus allen Assessments — Eingang fuer den PDF-Renderer."""

    assessments: tuple[ComplianceAssessment, ...]
    snapshot_summary: dict[str, object]

    def by_framework(
        self, framework: ComplianceFramework
    ) -> tuple[ComplianceAssessment, ...]:
        return tuple(a for a in self.assessments if a.requirement.framework is framework)

    def counts(self) -> dict[ComplianceCoverage, int]:
        counts: dict[ComplianceCoverage, int] = {c: 0 for c in ComplianceCoverage}
        for a in self.assessments:
            counts[a.coverage] += 1
        return counts


class ComplianceAssessor:
    """Erzeugt:class:`ComplianceAssessment`-Listen aus den aktuellen Daten."""

    def __init__(
        self,
        *,
        vendor_service: VendorService | None = None,
        avv_service: AvvService | None = None,
        subprocessor_service: SubprocessorService | None = None,
        offboarding_service: object | None = None,
        detection_repository: VendorDetectionRepository | None = None,
    ) -> None:
        self._vendors = vendor_service or VendorService()
        self._avvs = avv_service or AvvService()
        self._subs = subprocessor_service or SubprocessorService()
        # Off-Boarding-Service ist OPTIONAL — wird mit Iter 2d-i
        # eingefuehrt. Vor dem Merge ist die Klasse hier in master nicht
        # verfuegbar; per Duck-Typing greifen wir nur auf die zwei
        # benoetigten Methoden zu (``_repo.list_all`` + ``progress_per_vendor``).
        # Wenn nichts injiziert wird, versuchen wir einen Lazy-Import; faellt
        # der ImportError, bleiben die Off-Boarding-Counts 0.
        self._offb = offboarding_service or _try_load_offboarding_service()
        self._detections = detection_repository or VendorDetectionRepository()

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def _snapshot(self) -> _DataSnapshot:
        vendors = self._vendors.list_vendors()
        avvs = self._avvs.list_all()
        subs = self._subs.list_subprocessors()
        offboardings, completed_offb = _read_offboardings(self._offb)
        detections = self._detections.list_actionable()

        vendors_with_active_avv: set[int] = set()
        vendors_with_complete_checklist: set[int] = set()
        active_avvs = 0
        expired_avvs = 0
        overdue_avvs = 0
        for avv in avvs:
            if avv.status is AvvDocumentStatus.ACTIVE:
                active_avvs += 1
                if avv.id is not None:
                    vendors_with_active_avv.add(avv.vendor_id)
                    checklist = self._avvs.get_checklist(avv.id)
                    default_done = sum(
                        1 for e in checklist if not e.is_custom and e.is_present is True
                    )
                    # 10 Art28-Defaults gibt es; >=8 zaehlt als "completed".
                    if default_done >= 8:
                        vendors_with_complete_checklist.add(avv.vendor_id)
                if avv.renewal_status().value == "overdue":
                    overdue_avvs += 1
            elif avv.status is AvvDocumentStatus.EXPIRED:
                expired_avvs += 1

        concentration_findings = self._subs.concentration_findings()
        concentrated = sum(1 for f in concentration_findings if f.is_concentrated)

        return _DataSnapshot(
            vendor_count=len(vendors),
            critical_vendor_count=sum(1 for v in vendors if v.is_critical()),
            cloud_vendor_count=sum(
                1 for v in vendors if v.category is VendorCategory.CLOUD
            ),
            vendors_with_active_avv=vendors_with_active_avv,
            vendors_with_complete_checklist=vendors_with_complete_checklist,
            total_avvs=len(avvs),
            active_avvs=active_avvs,
            expired_avvs=expired_avvs,
            overdue_avvs=overdue_avvs,
            subprocessor_count=len(subs),
            concentrated_subprocessor_count=concentrated,
            actionable_detection_count=len(detections),
            has_any_detection=any(self._detections.list_all()),
            offboarding_count=offboardings,
            completed_offboarding_count=completed_offb,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess_all(self) -> ComplianceReport:
        snap = self._snapshot()
        assessments = tuple(
            _ASSESSMENT_RULES[req.identifier](req, snap)
            for req in COMPLIANCE_REQUIREMENTS
        )
        return ComplianceReport(
            assessments=assessments,
            snapshot_summary={
                "vendor_count": snap.vendor_count,
                "critical_vendor_count": snap.critical_vendor_count,
                "active_avvs": snap.active_avvs,
                "overdue_avvs": snap.overdue_avvs,
                "subprocessor_count": snap.subprocessor_count,
                "concentrated_subprocessors": snap.concentrated_subprocessor_count,
                "completed_offboardings": snap.completed_offboarding_count,
            },
        )


# ---------------------------------------------------------------------------
# Heuristiken pro Anforderung — kompakt als kleine Funktionen
# ---------------------------------------------------------------------------


def _manual_review(
    req: ComplianceRequirement, _snap: _DataSnapshot
) -> ComplianceAssessment:
    return ComplianceAssessment(
        requirement=req,
        coverage=ComplianceCoverage.MANUAL_REVIEW,
        evidence=(
            "Procedural — automatische Bewertung aus Tool-Daten nicht moeglich. "
            "Bitte extern dokumentieren und im Audit-Ordner ablegen."
        ),
    )


def _assess_gvsc_04(
    req: ComplianceRequirement, snap: _DataSnapshot
) -> ComplianceAssessment:
    # Kritikalitaets-Bewertung vorhanden: jeder Vendor hat criticality_score
    # (Domain-Constraint 1-5). Echtes Signal: >=3 Vendoren UND mindestens einer
    # als kritisch (>=4) markiert.
    if snap.vendor_count == 0:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.GAP,
            evidence="Noch keine Vendoren erfasst.",
            details={"vendor_count": 0},
        )
    if snap.vendor_count >= 3 and snap.critical_vendor_count >= 1:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.COVERED,
            evidence=(
                f"{snap.vendor_count} Vendoren erfasst, "
                f"{snap.critical_vendor_count} davon als kritisch eingestuft."
            ),
            details={
                "vendor_count": snap.vendor_count,
                "critical_vendor_count": snap.critical_vendor_count,
            },
        )
    return ComplianceAssessment(
        requirement=req,
        coverage=ComplianceCoverage.PARTIAL,
        evidence=(
            f"{snap.vendor_count} Vendor(en) erfasst, "
            f"davon {snap.critical_vendor_count} als kritisch. "
            "Empfehlung: mindestens 3 Vendoren und 1 kritischer Eintrag."
        ),
        details={
            "vendor_count": snap.vendor_count,
            "critical_vendor_count": snap.critical_vendor_count,
        },
    )


def _avv_coverage_ratio(snap: _DataSnapshot) -> float:
    if snap.vendor_count == 0:
        return 0.0
    return len(snap.vendors_with_active_avv) / snap.vendor_count


def _assess_gvsc_05(
    req: ComplianceRequirement, snap: _DataSnapshot
) -> ComplianceAssessment:
    ratio = _avv_coverage_ratio(snap)
    details = {
        "vendor_count": snap.vendor_count,
        "vendors_with_avv": len(snap.vendors_with_active_avv),
        "coverage_pct": int(ratio * 100),
    }
    if snap.vendor_count == 0:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.GAP,
            evidence="Keine Vendoren erfasst.",
            details=details,
        )
    if ratio >= 0.8:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.COVERED,
            evidence=f"AVV-Quote {int(ratio * 100)}% (>=80% gilt als covered).",
            details=details,
        )
    if ratio >= 0.4:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.PARTIAL,
            evidence=(
                f"AVV-Quote {int(ratio * 100)}% — bei mind. 80% gilt die "
                "Anforderung als erfuellt."
            ),
            details=details,
        )
    return ComplianceAssessment(
        requirement=req,
        coverage=ComplianceCoverage.GAP,
        evidence=(
            f"AVV-Quote {int(ratio * 100)}% — unzureichend. Erst Vertraege "
            "abschliessen und im AVV-Tab erfassen."
        ),
        details=details,
    )


def _assess_gvsc_06(
    req: ComplianceRequirement, snap: _DataSnapshot
) -> ComplianceAssessment:
    if snap.has_any_detection:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.COVERED,
            evidence=(
                f"Auto-Detection lief und lieferte {snap.actionable_detection_count} "
                "aktive Vendor-Hinweise."
            ),
            details={"actionable_detections": snap.actionable_detection_count},
        )
    return ComplianceAssessment(
        requirement=req,
        coverage=ComplianceCoverage.GAP,
        evidence=(
            "Auto-Detection (Installed-Apps, MX-Records, Cert-Issuer) wurde "
            "noch nie ausgefuehrt. Im 'Auto-Detection'-Tab starten."
        ),
    )


def _assess_gvsc_07(
    req: ComplianceRequirement, snap: _DataSnapshot
) -> ComplianceAssessment:
    if snap.vendor_count == 0:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.GAP,
            evidence="Keine Vendoren erfasst.",
        )
    complete_ratio = len(snap.vendors_with_complete_checklist) / snap.vendor_count
    details = {
        "vendor_count": snap.vendor_count,
        "vendors_with_complete_checklist": len(snap.vendors_with_complete_checklist),
        "subprocessor_count": snap.subprocessor_count,
    }
    if complete_ratio >= 0.8 and snap.subprocessor_count >= 1:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.COVERED,
            evidence=(
                f"{int(complete_ratio * 100)}% der Vendoren haben eine "
                f"vollstaendige Art-28-Checkliste, {snap.subprocessor_count} "
                "Subprocessor(en) sind erfasst."
            ),
            details=details,
        )
    if complete_ratio >= 0.4:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.PARTIAL,
            evidence=(
                f"Art-28-Checklisten zu {int(complete_ratio * 100)}% "
                f"vollstaendig, {snap.subprocessor_count} Subprocessor(en)."
            ),
            details=details,
        )
    return ComplianceAssessment(
        requirement=req,
        coverage=ComplianceCoverage.GAP,
        evidence=(
            f"Art-28-Checklisten zu {int(complete_ratio * 100)}% vollstaendig "
            "— unzureichend. Checklisten pro AVV ausfuellen."
        ),
        details=details,
    )


def _assess_gvsc_10(
    req: ComplianceRequirement, snap: _DataSnapshot
) -> ComplianceAssessment:
    if snap.offboarding_count >= 1:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.COVERED,
            evidence=(
                f"{snap.offboarding_count} Off-Boarding-Prozess(e) dokumentiert "
                f"({snap.completed_offboarding_count} abgeschlossen)."
            ),
            details={
                "offboarding_count": snap.offboarding_count,
                "completed_offboarding_count": snap.completed_offboarding_count,
            },
        )
    return ComplianceAssessment(
        requirement=req,
        coverage=ComplianceCoverage.GAP,
        evidence=(
            "Noch kein Off-Boarding-Prozess dokumentiert. Off-Boarding pro "
            "Vendor ueber den Vendoren-Tab starten."
        ),
    )


def _assess_ops_a4(
    req: ComplianceRequirement, snap: _DataSnapshot
) -> ComplianceAssessment:
    # Heuristik: alle Cloud-Kategorie-Vendoren sollten einen aktiven AVV haben.
    # Wir vereinfachen: Anteil aller-Vendoren-mit-AVV als Proxy.
    ratio = _avv_coverage_ratio(snap)
    if snap.cloud_vendor_count == 0:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.GAP,
            evidence="Keine Cloud-Vendoren erfasst.",
        )
    if ratio >= 0.8:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.COVERED,
            evidence=(
                f"{snap.cloud_vendor_count} Cloud-Vendor(en), AVV-Quote "
                f"{int(ratio * 100)}%."
            ),
            details={
                "cloud_vendor_count": snap.cloud_vendor_count,
                "avv_ratio_pct": int(ratio * 100),
            },
        )
    return ComplianceAssessment(
        requirement=req,
        coverage=ComplianceCoverage.PARTIAL if ratio >= 0.4 else ComplianceCoverage.GAP,
        evidence=(
            f"{snap.cloud_vendor_count} Cloud-Vendor(en), AVV-Quote "
            f"{int(ratio * 100)}%."
        ),
        details={
            "cloud_vendor_count": snap.cloud_vendor_count,
            "avv_ratio_pct": int(ratio * 100),
        },
    )


def _assess_ops_a10(
    req: ComplianceRequirement, snap: _DataSnapshot
) -> ComplianceAssessment:
    return _assess_gvsc_10(req, snap)  # gleiche Heuristik


def _assess_orp_a7(
    req: ComplianceRequirement, snap: _DataSnapshot
) -> ComplianceAssessment:
    if snap.vendor_count >= 3 and snap.subprocessor_count >= 1:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.COVERED,
            evidence=(
                f"{snap.vendor_count} Vendor(en) und {snap.subprocessor_count} "
                "Subprocessor(en) dokumentiert."
            ),
            details={
                "vendor_count": snap.vendor_count,
                "subprocessor_count": snap.subprocessor_count,
            },
        )
    if snap.vendor_count >= 1:
        return ComplianceAssessment(
            requirement=req,
            coverage=ComplianceCoverage.PARTIAL,
            evidence=(
                f"{snap.vendor_count} Vendor(en), aber Subprocessor-Liste "
                "leer / unvollstaendig."
            ),
        )
    return ComplianceAssessment(
        requirement=req,
        coverage=ComplianceCoverage.GAP,
        evidence="Keine Vendoren erfasst.",
    )


_AssessmentRule = Callable[
    [ComplianceRequirement, _DataSnapshot], ComplianceAssessment
]


# ---------------------------------------------------------------------------
# Optional Off-Boarding-Bruecke (Iter 2d-i — auf master noch nicht da)
# ---------------------------------------------------------------------------


def _try_load_offboarding_service() -> object | None:
    """Versucht:class:`OffBoardingService` lazy zu laden.

    Vor Merge von (Iter 2d-i) ist die Klasse nicht im master —
    in dem Fall liefern wir ``None`` und der Compliance-Assessor zaehlt
    die Off-Boarding-bezogenen Anforderungen als GAP (statt MANUAL_REVIEW),
    weil ein Wert von 0 ein klares Daten-Signal ist.
    """
    try:
        from tools.supply_chain_monitor.application.offboarding_service import (  # noqa: PLC0415
            OffBoardingService,
        )

        return OffBoardingService()
    except (ImportError, AttributeError):
        _log.debug(
            "ComplianceAssessor: OffBoardingService nicht verfuegbar — "
            "Off-Boarding-Counts bleiben 0."
        )
        return None


def _read_offboardings(service: object | None) -> tuple[int, int]:
    """Liest Off-Boarding-Counts ueber die optionale Service-Bruecke.

    Returns:
        (total_count, completed_count). ``(0, 0)`` wenn der Service nicht
        verfuegbar ist oder fehlschlaegt.
    """
    if service is None:
        return (0, 0)
    repo = getattr(service, "_repo", None)
    list_all = getattr(repo, "list_all", None) if repo is not None else None
    if list_all is None or not callable(list_all):
        return (0, 0)
    try:
        offboardings = list(list_all())
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "ComplianceAssessor: _read_offboardings fehlgeschlagen: %s",
            type(exc).__name__,
        )
        return (0, 0)
    completed = sum(
        1
        for o in offboardings
        if getattr(o, "status", None) is not None
        and getattr(o.status, "value", None) == "completed"
    )
    return (len(offboardings), completed)

_ASSESSMENT_RULES: dict[str, _AssessmentRule] = {
    # NIST GV.SC
    "GV.SC-01": _manual_review,
    "GV.SC-02": _manual_review,
    "GV.SC-03": _manual_review,
    "GV.SC-04": _assess_gvsc_04,
    "GV.SC-05": _assess_gvsc_05,
    "GV.SC-06": _assess_gvsc_06,
    "GV.SC-07": _assess_gvsc_07,
    "GV.SC-08": _manual_review,
    "GV.SC-09": _manual_review,
    "GV.SC-10": _assess_gvsc_10,
    # BSI OPS.2.3
    "OPS.2.3.A2": _manual_review,
    "OPS.2.3.A4": _assess_ops_a4,
    "OPS.2.3.A6": _manual_review,
    "OPS.2.3.A10": _assess_ops_a10,
    # BSI ORP.5
    "ORP.5.A6": _manual_review,
    "ORP.5.A7": _assess_orp_a7,
}
