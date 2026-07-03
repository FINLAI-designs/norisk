"""measurement_report — Mess-Status-Report fuer Hardening-Checks Phase 4).

Strukturiert die:class:`HardeningCheck`-Ergebnisse nach ihrem MESS-Zustand,
damit nicht Gemessenes im Report + in der GUI sichtbar UND begruendet wird
(Owner-Prinzip R5/R6b): gemessen / offen-mit-Handlungsbedarf / bewusst-verzichtet
/ nicht-zutreffend. Komplementaer zum:mod:`storytelling_adapter`, der bewusst NUR
messbare Verstoesse in "Was tun?"-Karten wandelt — dieser Report macht die
NICHT-gemessene Flaeche transparent.

Pure Transformation: kein I/O, kein GUI, keine Seiteneffekte. Schicht:
``application/`` (analog storytelling_adapter).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tools.system_scanner.domain.entities import HardeningCheck
from tools.system_scanner.domain.enums import UnmeasuredReason

#: Reasons, die mit einem Admin-Recheck / per Phase-2-API behebbar sind und
#: daher in die Handlungsbedarf-Sektion gehoeren.
_NEEDS_ACTION_REASONS = (UnmeasuredReason.NEEDS_ADMIN, UnmeasuredReason.PARSE_FAILED)


@dataclass(frozen=True, slots=True)
class MeasurementReportItem:
    """Ein Check im Mess-Report.

    Attributes:
        check_id: Stabile ID (z.B. ``"SH-001"``).
        label: Menschen-lesbarer Check-Name.
        note: Kontext — bei gemessenen Checks das ``detail``, bei nicht
            gemessenen die Begruendung (``skip_reason`` bzw. ``detail``).
        reason: Mess-Ursache bei nicht gemessenen Checks; ``None`` = gemessen.
    """

    check_id: str
    label: str
    note: str
    reason: UnmeasuredReason | None


@dataclass(frozen=True, slots=True)
class MeasurementReportSections:
    """Mess-Report in vier Sektionen R6b).

    Attributes:
        measured: Tatsaechlich gemessene Checks (``measurable=True``).
        needs_action: Offen/behebbar (``NEEDS_ADMIN``/``PARSE_FAILED``) — der
            Nutzer kann hier per Admin-Recheck nachmessen.
        declined: Bewusst uebersprungen (``USER_DECLINED``) — mit Begruendung.
        not_applicable: Strukturell nicht zutreffend (``NOT_APPLICABLE``).
    """

    measured: tuple[MeasurementReportItem, ...]
    needs_action: tuple[MeasurementReportItem, ...]
    declined: tuple[MeasurementReportItem, ...]
    not_applicable: tuple[MeasurementReportItem, ...]

    @property
    def has_open_items(self) -> bool:
        """True wenn es offene (nachmessbare) Posten gibt — treibt das Banner."""
        return bool(self.needs_action)


def build_measurement_report(
    checks: Iterable[HardeningCheck],
) -> MeasurementReportSections:
    """Strukturiert Hardening-Checks nach Mess-Zustand in vier Sektionen.

    Args:
        checks: Ergebnis von:meth:`WindowsHardeningScanner.scan_all` o.Ae.

    Returns:
:class:`MeasurementReportSections`. Reihenfolge der Checks bleibt je
        Sektion erhalten.
    """
    measured: list[MeasurementReportItem] = []
    needs_action: list[MeasurementReportItem] = []
    declined: list[MeasurementReportItem] = []
    not_applicable: list[MeasurementReportItem] = []

    for check in checks:
        item = MeasurementReportItem(
            check_id=check.check_id,
            label=check.label or check.check_id,
            note=check.detail or check.skip_reason,
            reason=None if check.measurable else check.unmeasured_reason,
        )
        if check.measurable:
            measured.append(item)
        elif check.unmeasured_reason in _NEEDS_ACTION_REASONS:
            needs_action.append(item)
        elif check.unmeasured_reason == UnmeasuredReason.USER_DECLINED:
            declined.append(item)
        elif check.unmeasured_reason == UnmeasuredReason.NOT_APPLICABLE:
            not_applicable.append(item)

    return MeasurementReportSections(
        measured=tuple(measured),
        needs_action=tuple(needs_action),
        declined=tuple(declined),
        not_applicable=tuple(not_applicable),
    )


__all__ = [
    "MeasurementReportItem",
    "MeasurementReportSections",
    "build_measurement_report",
]
