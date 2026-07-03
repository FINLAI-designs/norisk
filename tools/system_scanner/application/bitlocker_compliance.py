"""
bitlocker_compliance — Compliance-Bewertung der BitLocker-Probe.

Iter 3f: Nimmt die Probe-Ergebnisse aus
:mod:`bitlocker_inspector` und mappt sie auf eine Compliance-Stufe, die
in der Scanner-GUI als Banner angezeigt wird.

Bewertungs-Logik (NoRisk-Audit-Paket-3 §6.3):
- Volumes nicht-verschluesselt → **KRITISCH** (DSGVO Art. 32-Risiko).
- Schlechte Schluessel-Verwahrung (nur TPM ohne Recovery-Backup) →
  **WARNUNG** (bei TPM-Defekt kein Recovery moeglich).
- Recovery-Key liegt im Microsoft-Account → **HINWEIS** (Schrems-II-/
  Cloud-Act-Bedenken bei Mandantendaten).
- AD-Account-Backup → **OK** (empfohlen fuer Kanzlei-Umgebung).
- Numerical-Password lokal → **OK_MIT_HINWEIS** (User muss den Ausdruck
  sicher verwahren).

Schichtzugehoerigkeit: application/ — darf domain + data + core
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from core.logger import get_logger
from tools.system_scanner.data.bitlocker_inspector import (
    BitLockerOverallStatus,
    BitLockerReport,
    BitLockerVolumeProbe,
    RecoveryKeyLocation,
    check_bitlocker_status,
)

# Re-Exports fuer GUI-Konsumenten — vermeidet Hex-Contract-Verletzung
# (gui darf nicht direkt aus data importieren).
__all__ = [
    "BitLockerComplianceLevel",
    "BitLockerComplianceService",
    "BitLockerOverallStatus",
    "BitLockerReport",
    "BitLockerVolumeAssessment",
    "BitLockerVolumeProbe",
    "RecoveryKeyLocation",
]

_log = get_logger(__name__)


class BitLockerComplianceLevel(Enum):
    """Compliance-Stufe pro Volume oder im Aggregat."""

    NOT_APPLICABLE = "not_applicable"  # Non-Windows
    UNKNOWN = "unknown"  # Probe nicht ausfuehrbar
    CRITICAL = "critical"  # Volume unverschluesselt
    WARNING = "warning"  # Schluessel-Backup mangelhaft
    INFO = "info"  # MS-Account / Cloud-Hinweis
    OK = "ok"  # Empfohlene Konfiguration

    @property
    def display_label(self) -> str:
        return self.value.upper()

    @property
    def severity_order(self) -> int:
        """Reihenfolge fuer Aggregation: hoehere Zahl = ernster."""
        return {
            BitLockerComplianceLevel.NOT_APPLICABLE: 0,
            BitLockerComplianceLevel.OK: 1,
            BitLockerComplianceLevel.INFO: 2,
            BitLockerComplianceLevel.WARNING: 3,
            BitLockerComplianceLevel.UNKNOWN: 3,
            BitLockerComplianceLevel.CRITICAL: 4,
        }[self]


@dataclass(frozen=True)
class BitLockerVolumeAssessment:
    """Bewertung eines einzelnen Volumes.

    Attributes:
        probe: Die:class:`BitLockerVolumeProbe`-Original-Daten.
        level::class:`BitLockerComplianceLevel`.
        message: User-lesbare Begruendung.
    """

    probe: BitLockerVolumeProbe
    level: BitLockerComplianceLevel
    message: str


@dataclass(frozen=True)
class BitLockerComplianceInfo:
    """Aggregierter Compliance-Befund fuer den Scanner-Banner.

    Attributes:
        report: Die:class:`BitLockerReport`-Roh-Daten (durchgeschleift
                       fuer Detail-Anzeigen).
        overall_level: Hoechste (= schwerste) Stufe aller Volumes.
        assessments: Pro-Volume-Bewertungen.
        banner_text: Klartext fuer den Scanner-Banner.
    """

    report: BitLockerReport
    overall_level: BitLockerComplianceLevel
    assessments: list[BitLockerVolumeAssessment] = field(default_factory=list)
    banner_text: str = ""

    @property
    def needs_attention(self) -> bool:
        """``True`` wenn mindestens WARNING."""
        return self.overall_level.severity_order >= (
            BitLockerComplianceLevel.WARNING.severity_order
        )


class BitLockerComplianceService:
    """Liefert eine:class:`BitLockerComplianceInfo` fuer das Scanner-UI."""

    def __init__(self, prober=check_bitlocker_status) -> None:  # noqa: ANN001
        """Initialisiert den Service.

        Args:
            prober: Optionale Callable, die einen:class:`BitLockerReport`
                liefert. Default: ``check_bitlocker_status`` aus dem
                Inspector-Modul. Tests koennen hier einen Mock injizieren.
        """
        self._prober = prober

    def gather(self) -> BitLockerComplianceInfo:
        """Fuehrt die Probe aus und bewertet die Ergebnisse."""
        report = self._prober()
        if report.status is BitLockerOverallStatus.NOT_APPLICABLE:
            return BitLockerComplianceInfo(
                report=report,
                overall_level=BitLockerComplianceLevel.NOT_APPLICABLE,
                assessments=[],
                banner_text=report.message,
            )
        if report.status is BitLockerOverallStatus.UNKNOWN:
            return BitLockerComplianceInfo(
                report=report,
                overall_level=BitLockerComplianceLevel.UNKNOWN,
                assessments=[],
                banner_text=report.message,
            )

        assessments = [_assess_volume(v) for v in report.volumes]
        overall_level = (
            max(
                (a.level for a in assessments),
                key=lambda lv: lv.severity_order,
            )
            if assessments
            else BitLockerComplianceLevel.UNKNOWN
        )
        return BitLockerComplianceInfo(
            report=report,
            overall_level=overall_level,
            assessments=assessments,
            banner_text=_build_banner_text(
                overall_level=overall_level,
                report_status=report.status,
                assessments=assessments,
            ),
        )


# ---------------------------------------------------------------------------
# Pure Bewertungs-Funktionen
# ---------------------------------------------------------------------------


def _assess_volume(
    probe: BitLockerVolumeProbe,
) -> BitLockerVolumeAssessment:
    """Bewertet ein einzelnes Volume."""
    if not probe.protection_on:
        return BitLockerVolumeAssessment(
            probe=probe,
            level=BitLockerComplianceLevel.CRITICAL,
            message=(
                f"Volume {probe.mount_point or '?'} ist NICHT "
                "BitLocker-geschuetzt — DSGVO Art. 32-Risiko."
            ),
        )
    location = probe.key_location
    if location is RecoveryKeyLocation.ACTIVE_DIRECTORY:
        return BitLockerVolumeAssessment(
            probe=probe,
            level=BitLockerComplianceLevel.OK,
            message=(
                f"Volume {probe.mount_point or '?'}: Recovery-Key in "
                "Active Directory hinterlegt (empfohlen)."
            ),
        )
    if location is RecoveryKeyLocation.MICROSOFT_ACCOUNT:
        return BitLockerVolumeAssessment(
            probe=probe,
            level=BitLockerComplianceLevel.INFO,
            message=(
                f"Volume {probe.mount_point or '?'}: Recovery-Key im "
                "Microsoft-Account — bei Mandantendaten Schrems-II-/"
                "Cloud-Act-Bedenken pruefen."
            ),
        )
    if location is RecoveryKeyLocation.LOCAL_NUMERICAL_ONLY:
        return BitLockerVolumeAssessment(
            probe=probe,
            level=BitLockerComplianceLevel.WARNING,
            message=(
                f"Volume {probe.mount_point or '?'}: nur lokaler "
                "Numerical-Recovery-Key — Ausdruck physisch und getrennt "
                "vom Geraet aufbewahren, KEIN Backup-Volume mit denselben "
                "Schluesseln."
            ),
        )
    if location is RecoveryKeyLocation.TPM_ONLY:
        return BitLockerVolumeAssessment(
            probe=probe,
            level=BitLockerComplianceLevel.WARNING,
            message=(
                f"Volume {probe.mount_point or '?'}: nur TPM-Schutz, kein "
                "Recovery-Backup. Bei TPM-Defekt sind Daten verloren — "
                "Recovery-Key separat hinterlegen (AD oder physischer Ausdruck)."
            ),
        )
    if location is RecoveryKeyLocation.NONE:
        return BitLockerVolumeAssessment(
            probe=probe,
            level=BitLockerComplianceLevel.CRITICAL,
            message=(
                f"Volume {probe.mount_point or '?'} ist geschuetzt, hat "
                "aber KEINEN Recovery-Key — bei Geraete-Defekt sind die "
                "Daten unwiederbringlich verloren."
            ),
        )
    return BitLockerVolumeAssessment(
        probe=probe,
        level=BitLockerComplianceLevel.UNKNOWN,
        message=(
            f"Volume {probe.mount_point or '?'}: Recovery-Lage konnte "
            "nicht klassifiziert werden — Protectors manuell pruefen."
        ),
    )


def _build_banner_text(
    *,
    overall_level: BitLockerComplianceLevel,
    report_status: BitLockerOverallStatus,
    assessments: list[BitLockerVolumeAssessment],
) -> str:
    """Banner-Text fuer das Scanner-Widget."""
    if overall_level is BitLockerComplianceLevel.OK:
        return (
            "BitLocker: alle Volumes geschuetzt mit empfohlener "
            "Recovery-Hinterlegung (AD)."
        )
    if overall_level is BitLockerComplianceLevel.INFO:
        critical_or_warning = [
            a
            for a in assessments
            if a.level
            in (
                BitLockerComplianceLevel.CRITICAL,
                BitLockerComplianceLevel.WARNING,
            )
        ]
        if not critical_or_warning:
            return (
                "BitLocker: aktiv, Recovery-Key liegt im Microsoft-Account "
                "— fuer Kanzlei-Daten Cloud-Risiken pruefen."
            )
    if overall_level is BitLockerComplianceLevel.WARNING:
        return _summarize_concerns(
            assessments,
            level=BitLockerComplianceLevel.WARNING,
            label="Warnung",
        )
    if overall_level is BitLockerComplianceLevel.CRITICAL:
        if report_status is BitLockerOverallStatus.NO_VOLUMES_PROTECTED:
            return (
                "BitLocker: KEIN Volume verschluesselt — sofortige "
                "Aktion erforderlich (DSGVO Art. 32)."
            )
        if report_status is BitLockerOverallStatus.PARTIALLY_PROTECTED:
            return _summarize_concerns(
                assessments,
                level=BitLockerComplianceLevel.CRITICAL,
                label="Kritisch",
            )
        return _summarize_concerns(
            assessments,
            level=BitLockerComplianceLevel.CRITICAL,
            label="Kritisch",
        )
    return "BitLocker-Status unklar — manuelle Pruefung empfohlen."


def _summarize_concerns(
    assessments: list[BitLockerVolumeAssessment],
    *,
    level: BitLockerComplianceLevel,
    label: str,
) -> str:
    """Aggregiert die ersten zwei Volumes mit dem gegebenen Level."""
    relevant = [a for a in assessments if a.level is level]
    if not relevant:
        return f"BitLocker: {label}-Stufe ohne Volume-Detail."
    if len(relevant) == 1:
        return f"BitLocker {label}: {relevant[0].message}"
    head = relevant[0].probe.mount_point or "?"
    rest_count = len(relevant) - 1
    return (
        f"BitLocker {label}: Volume {head} und {rest_count} "
        "weitere(s) Volume betroffen — Details im Scan-Report."
    )
