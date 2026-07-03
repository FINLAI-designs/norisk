"""hardening_overrides — Alternativen-Tools heben nicht-messbare Checks.

Ein vom Nutzer deklarierter:class:`ManualScannerEntry` (z. B. VeraCrypt als
ENCRYPTION, Sophos als FIREWALL) erfuellt den zugehoerigen Hardening-Check, der
sonst nicht messbar waere (BitLocker fehlt auf Home-Editionen, Windows-Firewall
durch Dritt-Firewall ersetzt).

 / Patrick-Entscheidungen:
  - Eine aktive Alternative hebt den Check **voll** auf ``passed=True``.
  - VORRANG: nur fuer NICHT messbare Checks — ein real messbarer Check behaelt
    seinen echten Wert (echte Messung gewinnt).

Pure Funktion: keine DB, keine GUI. Single-Source — wird VOR allen Konsumenten
(Score, Hard-Caps, Findings-Tabelle) auf die Check-Liste angewandt,
sodass alle dieselbe Wahrheit sehen.

Schicht: ``tools/system_scanner/application``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from core.logger import get_logger
from tools.system_scanner.application.windows_hardening_scanner import (
    SH_001_FIREWALL,
    SH_010_BITLOCKER,
)
from tools.system_scanner.domain.entities import HardeningCheck, ManualScannerEntry
from tools.system_scanner.domain.enums import (
    ComponentStatus,
    ComponentType,
    UnmeasuredReason,
)

log = get_logger(__name__)

#: ManualScannerEntry-Kategorie -> Hardening-Check, den eine aktive Alternative
#: erfuellt. ANTIVIRUS hat (noch) keinen SH-Check-Partner und wird ignoriert.
ALTERNATIVE_CHECK_BY_CATEGORY: dict[ComponentType, str] = {
    ComponentType.ENCRYPTION: SH_010_BITLOCKER,
    ComponentType.FIREWALL: SH_001_FIREWALL,
}


def apply_manual_overrides(
    checks: Iterable[HardeningCheck],
    manual_entries: Iterable[ManualScannerEntry],
) -> list[HardeningCheck]:
    """Hebt nicht-messbare Checks, fuer die eine aktive Alternative deklariert ist.

    Args:
        checks: Hardening-Check-Ergebnisse aus dem Scan.
        manual_entries: Manuell deklarierte Sicherheitskomponenten.

    Returns:
        Neue Check-Liste: betroffene NICHT-messbare Checks ersetzt durch
        ``passed=True, measurable=True`` (Quelle: Alternative). Real messbare
        Checks bleiben unveraendert (echte Messung gewinnt).
    """
    # Aktive Alternative je Check-ID (erste aktive Deklaration gewinnt).
    alt_name_by_check: dict[str, str] = {}
    for entry in manual_entries:
        if entry.status is not ComponentStatus.ACTIVE:
            continue
        check_id = ALTERNATIVE_CHECK_BY_CATEGORY.get(entry.category)
        if check_id and check_id not in alt_name_by_check:
            alt_name_by_check[check_id] = entry.name

    if not alt_name_by_check:
        return list(checks)

    result: list[HardeningCheck] = []
    for check in checks:
        alt_name = alt_name_by_check.get(check.check_id)
        # Nur greifen, wenn der Check NICHT messbar ist (echte Messung gewinnt).
        if alt_name and not check.measurable:
            log.debug(
                "Hardening-Override: %s erfuellt durch Alternative '%s'",
                check.check_id,
                alt_name,
            )
            result.append(
                replace(
                    check,
                    passed=True,
                    measurable=True,
                    detail=(
                        f"Erfuellt durch Alternative: {alt_name} (manuell deklariert)"
                    ),
                )
            )
        else:
            result.append(check)
    return result


def apply_user_decline(
    checks: Iterable[HardeningCheck],
    *,
    note: str = "",
) -> list[HardeningCheck]:
    """Markiert offene (NEEDS_ADMIN) Checks als bewusst nicht gemessen P5).

    Der Nutzer verzichtet im Mess-zuerst-Flow (Soft-Gate D4) bewusst auf die
    Admin-Messung. Betroffene Checks behalten ``measurable=False``, wechseln aber
    den Reason auf ``USER_DECLINED`` — sie zaehlen damit im Rating als Defizit
    (druecken die Coverage, P6a) und erscheinen im Report mit Begruendung (P6b).
    Nur ``NEEDS_ADMIN`` ist verzichtbar; ``PARSE_FAILED`` (Tool-/Locale-Grenze)
    bleibt unveraendert. Pure Funktion.

    Args:
        checks: Hardening-Check-Ergebnisse aus dem Scan.
        note: Optionale Begruendung fuer den Report (sonst Default-Text).

    Returns:
        Neue Check-Liste mit den offenen Checks als ``USER_DECLINED``.
    """
    begruendung = note or "Vom Nutzer bewusst nicht gemessen"
    result: list[HardeningCheck] = []
    for check in checks:
        if (
            not check.measurable
            and check.unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN
        ):
            result.append(
                replace(
                    check,
                    unmeasured_reason=UnmeasuredReason.USER_DECLINED,
                    skip_reason=begruendung,
                )
            )
        else:
            result.append(check)
    return result


__all__ = [
    "ALTERNATIVE_CHECK_BY_CATEGORY",
    "apply_manual_overrides",
    "apply_user_decline",
]
