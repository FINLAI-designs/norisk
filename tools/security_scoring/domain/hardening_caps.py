"""
hardening_caps — Hard-Cap-Logik fuer den Hardening Score Phase 2).

Hard-Caps schraenken den Hardening-Score-Gesamtwert bei kritischen Findings
ein, unabhaengig vom gewichteten Mittel. Beispiel: 95 Punkte gewichteter
Score sind viel, aber wenn eine kritische CVE (CVSS ≥ 9.0) offen ist,
zeigt das Dashboard maximal 40 Punkte ("Critical"-Stage).

Verhinderter Fehler: "false sense of security" bei hohem Mittelwert trotz
schwerer Einzel-Findings — siehe v2 §3.

5 Caps v2 §3):

================================== ===== ==============================
Condition Cap Datenquelle
================================== ===== ==============================
CVE CVSS ≥ 9.0 offen 40 ScoreComponent (cve_exposure / dependency_auditor)
Admin-Passwort in Breach-DB 35 ScoreComponent (password_policy)
RDP exponiert ohne MFA 50 ScanResult (Phase 3 SH-003)
Keine Firewall aktiv 60 ScanResult (Phase 3 SH-001)
≥ 3 kritische Findings gleichzeitig 25 Σ findings_critical aller Components
================================== ===== ==============================

**Niedrigster aktiver Cap gewinnt** (``min(cap_value for event in events)``).

Caps 3+4 sind Phase-3-abhaengig — solange ``scan_result is None``
liefern die Detector-Funktionen ``None`` und triggern keinen Cap.
Damit sind Caps 1+2+5 sofort produktiv, Caps 3+4 schalten sich mit
Phase 3 (System-Scanner) automatisch ein.

Architektur-Prinzip wie Phase 1: **additiv und pure**. Diese Funktionen
sind seiteneffektfrei und werden vom:func:`compute_hardening_score`-
Aufruf am Ende der Pipeline angewendet.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.security_scoring.domain.models import ScoreComponent
    from tools.system_scanner.domain.entities import ScanResult


# ---------------------------------------------------------------------------
# Cap-Schwellenwerte v2 §3)
# ---------------------------------------------------------------------------

CAP_CRITICAL_CVE: int = 40
CAP_ADMIN_PW_BREACH: int = 35
CAP_RDP_NO_MFA: int = 50
CAP_NO_FIREWALL: int = 60
CAP_THREE_CRITICAL: int = 25

#: Minimal-Schwelle fuer Cap-5 (Total-Critical-Findings).
#: v2 sagt "≥ 3" — also 3 oder mehr.
THREE_CRITICAL_THRESHOLD: int = 3

#: Hardening-Check-IDs aus:mod:`tools.system_scanner.domain.entities`
#: (Phase 3 §5). Werden von den Cap-Detectors als Schluessel
#: in ``ScanResult.hardening_checks`` benutzt.
HARDENING_CHECK_FIREWALL: str = "SH-001"
HARDENING_CHECK_RDP: str = "SH-003"


# ---------------------------------------------------------------------------
# Event-Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HardCapEvent:
    """Ein aktiver Hard-Cap, der den Score auf einen Maximalwert
    beschraenkt.

    Frozen + slots: unveraenderbar, speicherarm, hashable. Wird in
:attr:`HardeningScoreResult.hard_cap_events` an die GUI/PDF geliefert.

    Attributes:
        label: Menschen-lesbarer Cap-Name fuer GUI/PDF (z. B.
            ``"Kritische CVE (CVSS ≥ 9.0) offen"``). Deutsch, weil
            FINLAI-UI deutsch ist.
        cap_value: Maximaler Score-Wert (0-100) — der Cap clampt
            ``score`` auf diesen Wert (oder niedriger).
        triggered_by: Datenquelle/Source-Tool oder Check-ID, die den
            Cap ausgeloest hat (z. B. ``"cve_exposure"`` oder
            ``"SH-001"``). Fuer Audit-Logs + UI-Tooltips.
        details: Freier Zusatz-String, z. B. ``"3 kritische CVEs offen"``.
    """

    label: str
    cap_value: int
    triggered_by: str
    details: str = ""


# ---------------------------------------------------------------------------
# Cap-Detectors (pure)
# ---------------------------------------------------------------------------


def _detect_critical_cve_cap(
    components: list[ScoreComponent],
) -> HardCapEvent | None:
    """Cap 1: Kritische CVE (CVSS ≥ 9.0) offen.

    Datenquelle: ScoreComponents mit ``source_tool in {"cve_exposure",
    "dependency_auditor"}`` und ``findings_critical > 0``. Erstes
    Match gewinnt (alle weiteren wuerden den gleichen Cap setzen).

    Args:
        components: Alle ScoreComponents — auch ``data_available=False``
            werden geprueft, weil ein revoked-Cert mit data_available=False
            historische kritische CVEs trotzdem dokumentieren kann.
            Praktisch: ``findings_critical=0`` ist die Norm bei
            data_available=False, also kein Doppel-Match.

    Returns:
:class:`HardCapEvent` oder ``None`` wenn keine kritische
        CVE gefunden wurde.
    """
    for c in components:
        if c.source_tool not in {"cve_exposure", "dependency_auditor"}:
            continue
        if c.findings_critical > 0:
            return HardCapEvent(
                label="Kritische CVE (CVSS ≥ 9.0) offen",
                cap_value=CAP_CRITICAL_CVE,
                triggered_by=c.source_tool,
                details=f"{c.findings_critical} kritische Finding(s) bei {c.name}",
            )
    return None


def _detect_admin_pw_breach_cap(
    components: list[ScoreComponent],
) -> HardCapEvent | None:
    """Cap 2: Admin-Passwort in Breach-DB.

    Datenquelle: ``ScoreComponent.findings_critical > 0`` bei
    ``source_tool="password_policy"``. Heuristik: ein kritisches
    password_policy-Finding bedeutet typisch HIBP-Breach-Match auf
    einem Admin-Account (Severity-Mapping in
    ``password_service.PasswordSeverity.CRITICAL``).

    Returns:
:class:`HardCapEvent` oder ``None``.
    """
    for c in components:
        if c.source_tool != "password_policy":
            continue
        if c.findings_critical > 0:
            return HardCapEvent(
                label="Admin-Passwort in Breach-DB",
                cap_value=CAP_ADMIN_PW_BREACH,
                triggered_by="password_policy",
                details=f"{c.findings_critical} kritische Passwort-Finding(s)",
            )
    return None


def _detect_three_critical_findings_cap(
    components: list[ScoreComponent],
) -> HardCapEvent | None:
    """Cap 5: ≥ 3 kritische Findings gleichzeitig.

    Aggregiert ``findings_critical`` ueber alle aktiven
    (``data_available=True``) Components. Ab Schwelle
:data:`THREE_CRITICAL_THRESHOLD` (=3) triggert der Cap.

    Datenmodell-Hinweis: ``data_available=False``-Components werden
    ausgeschlossen — sonst koennten historisch persistierte Findings
    den Cap aktivieren, obwohl die Datenquelle aktuell nicht
    erreichbar ist.

    Returns:
:class:`HardCapEvent` oder ``None``.
    """
    beitraege = [
        (c.name, c.findings_critical)
        for c in components
        if c.data_available and c.findings_critical > 0
    ]
    total = sum(n for _, n in beitraege)
    if total >= THREE_CRITICAL_THRESHOLD:
        # Benennt, WO die kritischen Findings liegen (Patrick 2026-06-27:
        # "so ist es nicht informativ") — absteigend nach Anzahl, damit die
        # GUI/PDF (rendert ``details`` direkt) die Quellen statt nur die Summe
        # zeigt. Quelle: dieselben ScoreComponents wie der Kategorie-Breakdown.
        beitraege.sort(key=lambda x: (-x[1], x[0]))
        quellen = ", ".join(f"{name} ({n})" for name, n in beitraege)
        return HardCapEvent(
            label=f"≥ {THREE_CRITICAL_THRESHOLD} kritische Findings gleichzeitig",
            cap_value=CAP_THREE_CRITICAL,
            triggered_by="aggregate",
            details=f"{total} kritische Findings: {quellen}",
        )
    return None


def _find_hardening_check(scan_result: ScanResult, check_id: str):
    """Sucht einen ``HardeningCheck`` per ``check_id`` im Scan-Ergebnis.

    Returns:
        Den zugehoerigen:class:`HardeningCheck` oder ``None`` wenn nicht
        gefunden. Caller wertet das ``passed``-Feld aus, um zu
        entscheiden ob der Cap aktiv ist.
    """
    for check in scan_result.hardening_checks:
        if check.check_id == check_id:
            return check
    return None


def _detect_rdp_no_mfa_cap(
    scan_result: ScanResult | None,
) -> HardCapEvent | None:
    """Cap 3: RDP exponiert ohne MFA (aktiviert in Phase 3.1).

    Datenquelle::class:`ScanResult.hardening_checks` mit
:data:`HARDENING_CHECK_RDP` (``"SH-003"``). Wenn der Check
    ``passed=False`` hat (= RDP ist aktiviert UND ohne MFA), wird der
    Cap aktiviert.

    Args:
        scan_result: Optionales Scan-Ergebnis. ``None`` bedeutet:
            System-Scanner wurde nicht aufgerufen — Cap bleibt inaktiv
            (sicherheitsneutraler Default).

    Returns:
:class:`HardCapEvent` wenn SH-003 fehlgeschlagen ist, sonst
        ``None``.
    """
    if scan_result is None:
        return None
    check = _find_hardening_check(scan_result, HARDENING_CHECK_RDP)
    if check is None or check.passed or not check.measurable:
        # ein nicht messbarer RDP/Firewall-Check (z.B. Registry/netsh
        # ohne Adminrechte lesbar) darf NIE den Hard-Cap ausloesen.
        return None
    # Nur die UNNOETIGE Exposition (CRITICAL) deckelt den Score. Ein
    # nachweislich GENUTZTES RDP stuft check_rdp als HIGH ein (sichtbarer Befund
    # + „absichern", aber kein Cap) — Patrick-Entscheid 2026-06-26: ein
    # benoetigter, abgesicherter Fernzugriff darf den Score nicht wie eine
    # unnoetige Exposition kappen. severity != CRITICAL -> kein Cap.
    # Severity-Import lazy (analog hardening_aggregation.py) — kein Domain-
    # Coupling im Modul-Top.
    from core.security.severity import Severity  # noqa: PLC0415

    if check.severity != Severity.CRITICAL:
        return None
    return HardCapEvent(
        label="RDP exponiert ohne MFA",
        cap_value=CAP_RDP_NO_MFA,
        triggered_by=HARDENING_CHECK_RDP,
        details=check.detail or "RDP-Port erreichbar, keine MFA erkannt",
    )


def _detect_no_firewall_cap(
    scan_result: ScanResult | None,
) -> HardCapEvent | None:
    """Cap 4: Keine Firewall aktiv (aktiviert in Phase 3.1).

    Datenquelle::class:`ScanResult.hardening_checks` mit
:data:`HARDENING_CHECK_FIREWALL` (``"SH-001"``). Wenn der Check
    ``passed=False`` hat (= mindestens ein Firewall-Profil ist
    deaktiviert), wird der Cap aktiviert.

    Args:
        scan_result: Optionales Scan-Ergebnis. ``None`` → Cap inaktiv.

    Returns:
:class:`HardCapEvent` wenn SH-001 fehlgeschlagen ist, sonst
        ``None``.
    """
    if scan_result is None:
        return None
    check = _find_hardening_check(scan_result, HARDENING_CHECK_FIREWALL)
    if check is None or check.passed or not check.measurable:
        # ein nicht messbarer RDP/Firewall-Check (z.B. Registry/netsh
        # ohne Adminrechte lesbar) darf NIE den Hard-Cap ausloesen.
        return None
    return HardCapEvent(
        label="Keine Firewall aktiv",
        cap_value=CAP_NO_FIREWALL,
        triggered_by=HARDENING_CHECK_FIREWALL,
        details=check.detail or "Windows-Firewall-Profil deaktiviert",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def apply_hard_caps(
    score: float,
    components: list[ScoreComponent],
    scan_result: ScanResult | None = None,
) -> tuple[float, list[HardCapEvent]]:
    """Wendet alle anwendbaren Hard-Caps auf den Score an.

    Pipeline:

    1. Alle 5 Detector-Funktionen aufrufen.
    2. Anwesende Events sammeln (None werden ausgefiltert).
    3. Niedrigster ``cap_value`` gewinnt.
    4. ``score`` auf ``min(cap_value, score)`` geclampt.

    Die vollstaendige Event-Liste (nicht nur der gewinnende Cap) wird
    zurueckgegeben — die GUI zeigt typisch alle aktiven Caps als
    Tooltip/Hinweis, nicht nur den lowest.

    Args:
        score: Gewichteter Hardening-Score-Gesamtwert vor Cap-
            Anwendung (0-100).
        components: Alle ScoreComponents — Detectors 1+2+5 nutzen
            diese.
        scan_result: Optionales:class:`ScanResult` aus
:mod:`tools.system_scanner`. Pflicht fuer Caps 3+4 — wenn
            ``None``, bleiben diese Caps inaktiv.

    Returns:
        Tuple aus ``(geclampter_score, alle_aktiven_cap_events)``.
        Wenn keine Caps triggern, ist ``score`` unveraendert und die
        Event-Liste leer.
    """
    events: list[HardCapEvent] = []

    # Component-basierte Detectors (immer pruefen)
    component_detectors = (
        _detect_critical_cve_cap,
        _detect_admin_pw_breach_cap,
        _detect_three_critical_findings_cap,
    )
    for detector in component_detectors:
        event = detector(components)
        if event is not None:
            events.append(event)

    # Scan-Result-basierte Detectors (nur wenn scan_result vorhanden)
    scan_detectors = (
        _detect_rdp_no_mfa_cap,
        _detect_no_firewall_cap,
    )
    for scan_detector in scan_detectors:
        event = scan_detector(scan_result)
        if event is not None:
            events.append(event)

    if not events:
        return score, []

    lowest_cap = min(e.cap_value for e in events)
    capped_score = min(score, float(lowest_cap))
    return capped_score, events
