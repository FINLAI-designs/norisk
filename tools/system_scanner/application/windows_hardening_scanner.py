"""
windows_hardening_scanner — 10 Windows-Hardening-Checks Phase 3.3).

Implementiert SH-001..SH-010 aus §5 / [[NoRisk_HARDENING_SCORE]].
Pure Orchestrierung: jeder Check ruft einen oder mehrere
:class:`IHardeningProbe`-Methoden auf und buendelt das Ergebnis in
einen:class:`HardeningCheck`.

Die 10 Checks:

================ ================================================ ============= =======
Check-ID Beschreibung Methode Sev
================ ================================================ ============= =======
SH-001 Windows Firewall aktiv (alle Profile) netsh CRIT
SH-002 UAC aktiviert + EnableLUA = 1 Registry HIGH
SH-003 RDP deaktiviert (fDenyTSConnections = 1) Registry CRIT
SH-004 Windows-Update funktionsfaehig (Dienst+Frische) Registry HIGH
SH-005 SMBv1 deaktiviert (EnableSMB1Protocol = False) PowerShell CRIT
SH-006 Gastkonto deaktiviert (net user Guest) Command MED
SH-007 Passwort-Min-Laenge >= 8 (net accounts) Command HIGH
SH-008 Autorun deaktiviert (NoDriveTypeAutoRun = 255) Registry MED
SH-009 Lokale Admins <= 2 (net localgroup) Command HIGH
SH-010 BitLocker aktiv auf C: (manage-bde -status) Command MED
================ ================================================ ============= =======

Schichtzugehoerigkeit: application/. Die Production-Adapter
(:class:`WindowsHardeningProbe`) leben in data/. Tests verwenden den
:class:`MockHardeningProbe` (Phase 3.2).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from core.logger import get_logger
from core.probes.hardening_probe import HIVE_HKLM
from core.security.severity import Severity
from tools.system_scanner.domain.entities import HardeningCheck, OSInfo, ScanResult
from tools.system_scanner.domain.enums import OSPlatform, UnmeasuredReason

if TYPE_CHECKING:
    from core.probes.hardening_probe import IHardeningProbe, ProbeResult

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Check-IDs (sync mit hardening_caps.HARDENING_CHECK_* aus Phase 3.1)
# ---------------------------------------------------------------------------

SH_001_FIREWALL: Final[str] = "SH-001"
SH_002_UAC: Final[str] = "SH-002"
SH_003_RDP: Final[str] = "SH-003"
SH_004_AUTO_UPDATE: Final[str] = "SH-004"
SH_005_SMBV1: Final[str] = "SH-005"
SH_006_GUEST_ACCOUNT: Final[str] = "SH-006"
SH_007_PASSWORD_POLICY: Final[str] = "SH-007"
SH_008_AUTORUN: Final[str] = "SH-008"
SH_009_LOCAL_ADMINS: Final[str] = "SH-009"
SH_010_BITLOCKER: Final[str] = "SH-010"

#: Maximale Anzahl lokaler Admin-Accounts ohne Warnung.
_MAX_LOCAL_ADMINS: Final[int] = 2

#: Minimale Passwort-Laenge.
_MIN_PASSWORD_LENGTH: Final[int] = 8

#: Locale-freie PowerShell-Primaerabfragen Phase 2) — als Konstanten,
#: damit Tests denselben String an die MockHardeningProbe geben koennen.
_PS_FIREWALL_PROFILES: Final[str] = (
    "@(Get-NetFirewallProfile -ErrorAction Stop | "
    "ForEach-Object { if ($_.Enabled) { '1' } else { '0' } }) -join ','"
)
_PS_GUEST_ACCOUNT: Final[str] = (
    "$u = Get-LocalUser -ErrorAction Stop | "
    "Where-Object { $_.SID.Value -like '*-501' }; "
    "if ($null -eq $u) { 'absent' } "
    "elseif ($u.Enabled) { 'enabled' } else { 'disabled' }"
)
_PS_LOCAL_ADMINS_COUNT: Final[str] = (
    "@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop).Count"
)
_PS_BITLOCKER_C: Final[str] = (
    "(Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop).ProtectionStatus"
)
#: EditionID aus der Registry — locale-frei + OHNE Adminrechte lesbar. Home-
#: Editionen liefern "Core"/"CoreN"/"CoreSingleLanguage"/"CoreCountrySpecific";
#: dort gibt es BitLocker strukturell nicht (SH-010 -> NOT_APPLICABLE).
_PS_EDITION_ID: Final[str] = (
    "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
    "-Name EditionID -ErrorAction Stop).EditionID"
)

# --- SH-004 Windows-Update — admin-frei lesbare Registry-Signale ----
#: Basis-Key der Windows-Update-Agent-Resultate.
_WU_AUTO_UPDATE_KEY: Final[str] = (
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update"
)
#: Subkeys mit dem Zeitstempel der letzten ERFOLGREICHEN Suche bzw. Installation.
#: Vom Update-Agent geschrieben (auch auf Consumer-Maschinen vorhanden),
#: world-readable (kein Admin), Format ``"%Y-%m-%d %H:%M:%S"`` in UTC (locale-frei).
_WU_RESULTS_DETECT_KEY: Final[str] = _WU_AUTO_UPDATE_KEY + "\\Results\\Detect"
_WU_RESULTS_INSTALL_KEY: Final[str] = _WU_AUTO_UPDATE_KEY + "\\Results\\Install"
_WU_LAST_SUCCESS_VALUE: Final[str] = "LastSuccessTime"
_WU_AU_OPTIONS_VALUE: Final[str] = "AUOptions"
_WU_TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
#: Service-Key des Windows-Update-Dienstes. ``Start`` (REG_DWORD) ist auf JEDEM
#: Windows vorhanden + world-readable -> SH-004 ist damit immer messbar.
_WUAUSERV_START_KEY: Final[str] = "SYSTEM\\CurrentControlSet\\Services\\wuauserv"
_WUAUSERV_START_VALUE: Final[str] = "Start"
#: Start-Typ 4 = ``Disabled`` (Dienst ausgeschaltet -> Updates kommen nicht an).
_SERVICE_START_DISABLED: Final[str] = "4"
#: AUOptions-Werte, die KEIN automatisches Update bedeuten (managed/WSUS-Overlay):
#: 1 = Disabled, 2 = Notify before downloading (kein Auto). 3/4/5 = Auto.
_AU_OPTIONS_NO_AUTO: Final[frozenset[str]] = frozenset({"1", "2"})
#: Maximales Alter der letzten erfolgreichen Update-SUCHE ohne Verstoss (Tage).
#: Ein gesundes Windows sucht alle 1-3 Tage; 14 Tage puffern Standby/Abwesenheit.
_MAX_SEARCH_AGE_DAYS: Final[int] = 14
#: Obergrenze fuer ein plausibles Such-Alter (~10 Jahre). Ein Timestamp aelter
#: als das (Windows schreibt ``1601-01-01`` als „nie gelaufen"-Sentinel) ODER in
#: der Zukunft (Uhr-Skew/Manipulation) ist KEIN Beweis einer erfolgreichen Suche
#: -> wird wie „keine verlaessliche Suche verzeichnet" behandelt (fail-closed).
_PLAUSIBLE_MAX_SEARCH_AGE_DAYS: Final[int] = 3650

# --- SH-003 RDP — admin-frei: Konfiguration + Listener/aktive Sitzung -
#: Terminal-Server-Policy-Key. ``fDenyTSConnections=1`` -> RDP verweigert
#: (sicher), ``=0`` -> erlaubt (Risiko). Liegt unter HKLM\\Control, ueblicherweise
#: world-readable.
_RDP_TERMINAL_SERVER_KEY: Final[str] = (
    "SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
)
_RDP_DENY_VALUE: Final[str] = "fDenyTSConnections"
#: Service-Key des RDP-Diensts (TermService). ``Start`` (REG_DWORD) ist
#: world-readable; ``Start=4`` (Disabled) -> RDP-Dienst aus -> kein Fernzugriff.
#: Wiederverwendet:data:`_SERVICE_START_DISABLED` ("4") aus SH-004.
_RDP_TERMSERVICE_KEY: Final[str] = "SYSTEM\\CurrentControlSet\\Services\\TermService"
_RDP_TERMSERVICE_START_VALUE: Final[str] = "Start"
#: RDP-Standardport. Listener auf 3389 = von aussen erreichbar; eine ESTABLISHED-
#: Verbindung darauf = RDP wird gerade aktiv genutzt (eingehende Sitzung).
_RDP_PORT: Final[int] = 3389
#: Locale-freie, admin-frei ausfuehrbare PowerShell-Probe: zaehlt Listen- und
#: Established-TCP-Verbindungen auf dem RDP-Port. ``-State`` filtert ueber ein
#: Enum (sprachneutral). Die Established-Zahl zaehlt NUR Verbindungen mit einer
#: NICHT-Loopback-RemoteAddress (127.0.0.1/::1 ausgeschlossen) -> ein lokaler
#: Self-Connect kann den „RDP genutzt"-Pfad (HIGH, kein Cap) NICHT erschleichen
#: (Review). Ausgabe: ``"<listen>,<established>"`` (zwei Zahlen).
#: Effekt::func:`_classify_rdp` wertet den Listener als echte Angriffsflaeche und
#: die Remote-Sitzung als Nutzung;:func:`_parse_rdp_port_state` parst exakt dieses
#: Format -> Skript-/Port-Aenderung muss dort nachgezogen werden.
_PS_RDP_PORT_STATE: Final[str] = (
    f"$p={_RDP_PORT}; "
    "$l=@(Get-NetTCPConnection -LocalPort $p -State Listen "
    "-ErrorAction SilentlyContinue).Count; "
    "$e=@(Get-NetTCPConnection -LocalPort $p -State Established "
    "-ErrorAction SilentlyContinue | Where-Object "
    "{ $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' }).Count; "
    '"$l,$e"'
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class WindowsHardeningScanner:
    """Fuehrt die 10 Windows-Hardening-Checks aus.

    Stateless — alle System-Aufrufe gehen ueber den injizierten
:class:`IHardeningProbe`. Damit deterministisch testbar (Mock-
    Probe) und plattform-unabhaengig (Production-Adapter ist
    Windows-only, Mock laeuft ueberall).

    Args:
        probe: Implementation von:class:`IHardeningProbe`. Im
            Production::class:`WindowsHardeningProbe`. In Tests:
:class:`MockHardeningProbe`.
    """

    def __init__(self, probe: IHardeningProbe) -> None:
        self._probe = probe

    # ------------------------------------------------------------------
    # Public API — alle 10 Checks
    # ------------------------------------------------------------------

    def scan_all(self) -> list[HardeningCheck]:
        """Fuehrt alle 10 SH-Checks aus und gibt die Ergebnisse zurueck.

        Reihenfolge in der zurueckgegebenen Liste ist SH-001 → SH-010.
        Probe-Fehler eines einzelnen Checks brechen den Scan **nicht**
        ab — der betroffene Check landet mit ``passed=False`` und
        einem detail-String wie ``"Probe-Fehler:..."`` in der Liste.

        Returns:
            10:class:`HardeningCheck`-Instanzen.
        """
        return [
            self.check_firewall(),
            self.check_uac(),
            self.check_rdp(),
            self.check_auto_update(),
            self.check_smbv1(),
            self.check_guest_account(),
            self.check_password_policy(),
            self.check_autorun(),
            self.check_local_admins(),
            self.check_bitlocker(),
        ]

    # ------------------------------------------------------------------
    # SH-001 — Windows Firewall
    # ------------------------------------------------------------------

    def check_firewall(self) -> HardeningCheck:
        """SH-001: Windows Firewall fuer alle 3 Profile aktiv.

        Primaer locale-frei via ``Get-NetFirewallProfile`` (boolean ``.Enabled``
        je Profil — sprachneutral Phase 2). Fallback: ``netsh``-Output
        (locale-tolerant geparst); ist auch der nicht eindeutig auslesbar ->
        measurable=False/PARSE_FAILED (kein erfundener Verstoss/Cap-4).
        """
        ps = self._probe.run_powershell(_PS_FIREWALL_PROFILES)
        if ps.success and ps.stdout.strip():
            tokens = [t.strip() for t in ps.stdout.strip().split(",") if t.strip()]
            # Vollstaendigkeits-Garantie wie der netsh-Fallback (state_on >= 3):
            # GENAU 3 Profile (Domain/Private/Public) UND jeder Token eindeutig
            # 0/1. Sonst KEIN PASS (sonst false-secure auf einem CRITICAL-Check) —
            # auf den netsh-Fallback durchfallen lassen, der unklare Ausgaben
            # selbst als nicht-messbar behandelt.
            if len(tokens) == 3 and all(t in ("0", "1") for t in tokens):
                off = tokens.count("0")
                return HardeningCheck(
                    check_id=SH_001_FIREWALL,
                    label="Windows Firewall aktiv (alle Profile)",
                    passed=off == 0,
                    severity=Severity.CRITICAL,
                    detail=(
                        "Alle 3 Profile aktiv (Get-NetFirewallProfile)"
                        if off == 0
                        else f"{off} Firewall-Profil(e) deaktiviert (Get-NetFirewallProfile)"
                    ),
                )
        # Fallback: netsh (locale-tolerant).
        result = self._probe.run_command(
            "netsh", ["advfirewall", "show", "allprofiles", "state"]
        )
        if not result.success:
            return self._probe_failed(
                SH_001_FIREWALL,
                "Windows Firewall aktiv (alle Profile)",
                Severity.CRITICAL,
                result.error,
            )
        # netsh-Output ist locale-abhaengig — Label UND Wert. Verifiziert auf
        # deutschem Win11: "Status EIN"
        # (Wert "EIN"/"AUS", NICHT "ON"/"OFF"). Englisch: "State... ON"/"OFF".
        # Frueher matchte die Regex nur "on"/"off" -> auf DE-Locale fiel SH-001
        # faelschlich auf "nicht messbar" zurueck (Firewall-False-Negative,
        # wenn die locale-freie Get-NetFirewallProfile-Primaerprobe ausfiel).
        lower = result.stdout.lower()
        # Whitespace-/Label-tolerant: DE "Status"/EN "State"; Wert on/ein bzw. off/aus.
        state_on = len(re.findall(r"(?:state|status)\s+(?:on|ein)\b", lower))
        state_off = len(re.findall(r"(?:state|status)\s+(?:off|aus)\b", lower))
        if state_on >= 3 and state_off == 0:
            return HardeningCheck(
                check_id=SH_001_FIREWALL,
                label="Windows Firewall aktiv (alle Profile)",
                passed=True,
                severity=Severity.CRITICAL,
                detail="Alle 3 Profile (Domain/Private/Public) aktiv",
            )
        if state_off >= 1:
            return HardeningCheck(
                check_id=SH_001_FIREWALL,
                label="Windows Firewall aktiv (alle Profile)",
                passed=False,
                severity=Severity.CRITICAL,
                detail=f"{state_off} Firewall-Profil(e) deaktiviert",
            )
        # netsh lief, aber der Status liess sich NICHT eindeutig auslesen (z.B.
        # nicht-DE/EN-Locale + Get-NetFirewallProfile nicht verfuegbar). NICHT als
        # Verstoss werten -> kein erfundenes KRITISCH/Cap-4. measurable=False.
        return HardeningCheck(
            check_id=SH_001_FIREWALL,
            label="Windows Firewall aktiv (alle Profile)",
            passed=False,
            severity=Severity.CRITICAL,
            detail=(
                "Firewall-Status nicht eindeutig auslesbar (Spracheinstellung) "
                "— als nicht messbar gewertet"
            ),
            measurable=False,
            unmeasured_reason=UnmeasuredReason.PARSE_FAILED,
        )

    # ------------------------------------------------------------------
    # SH-002 — UAC
    # ------------------------------------------------------------------

    def check_uac(self) -> HardeningCheck:
        """SH-002: UAC ist aktiviert (EnableLUA = 1)."""
        value = self._probe.read_registry_value(
            HIVE_HKLM,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA",
        )
        if value is None:
            return self._registry_missing(
                SH_002_UAC,
                "UAC aktiviert",
                Severity.HIGH,
                "EnableLUA",
            )
        passed = value == "1"
        return HardeningCheck(
            check_id=SH_002_UAC,
            label="UAC aktiviert",
            passed=passed,
            severity=Severity.HIGH,
            detail=f"EnableLUA = {value}",
        )

    # ------------------------------------------------------------------
    # SH-003 — RDP
    # ------------------------------------------------------------------

    def check_rdp(self) -> HardeningCheck:
        """SH-003: RDP deaktiviert ODER bewusst genutzt-und-abgesichert.

        Frueher galt jedes ``fDenyTSConnections=0`` pauschal als CRITICAL und
        deckelte den Score (Cap 3). Jetzt wird die *Erforderlichkeit* mit
        gemessen — alle drei Signale admin-frei:

        * **Konfiguration** (``fDenyTSConnections`` + ``TermService\\Start``):
          Ist RDP ueberhaupt aktiviert?
        * **Listener** (TCP 3389 im Zustand *Listen*): Von aussen erreichbar?
        * **Aktive Sitzung** (TCP 3389 *Established*): Wird RDP gerade genutzt?

        Daraus drei Faelle (Patrick-Entscheid 2026-06-26):

        * RDP aus (Policy ``deny`` ODER Dienst deaktiviert) -> bestanden.
        * RDP aktiviert UND nachweislich in Nutzung (Established) -> Befund
          ``HIGH`` mit „absichern"-Empfehlung, aber **kein Hard-Cap** — ein
          benoetigter Fernzugriff darf den Score nicht wie eine unnoetige
          Exposition kappen.
        * RDP erreichbar (Listener auf 3389), aber ungenutzt -> ``CRITICAL``
          mit „abschalten"-Empfehlung (loest Cap 3 aus).
        * **Kein Listener** auf 3389 -> kein realer Fernzugriff -> bestanden,
          KEIN Cap — UNABHAENGIG vom Policy-Bit. Patrick 2026-06-26: „wenn es
          kein RDP gibt, muss der Cap weg." Die blosse ``fDenyTSConnections=0``-
          Policy ohne lauschenden Dienst ist KEINE aktive Exposition.

        Der Hard-Cap setzt also einen nachgewiesenen LISTENER voraus. Schlaegt
        die Listener-Probe fehl UND ist die Policy nicht ``deny``, gilt der
        Check ehrlich als nicht messbar (NEEDS_ADMIN) — kein fail-closed-Cap auf
        einem nicht erreichbaren RDP.
        """
        fdeny = self._probe.read_registry_value(
            HIVE_HKLM, _RDP_TERMINAL_SERVER_KEY, _RDP_DENY_VALUE
        )
        service_start = self._probe.read_registry_value(
            HIVE_HKLM, _RDP_TERMSERVICE_KEY, _RDP_TERMSERVICE_START_VALUE
        )
        listening, established = _parse_rdp_port_state(
            self._probe.run_powershell(_PS_RDP_PORT_STATE)
        )

        classified = _classify_rdp(
            fdeny=fdeny,
            service_start=service_start,
            listening=listening,
            established=established,
        )
        if classified is None:
            # Weder Konfiguration lesbar noch Listener beobachtbar -> ehrlich
            # nicht messbar (statt faelschlich „RDP aktiviert", wenn nur der
            # Registry-Read scheiterte).
            return self._registry_missing(
                SH_003_RDP,
                "RDP deaktiviert",
                Severity.CRITICAL,
                _RDP_DENY_VALUE,
            )
        passed, severity, detail = classified
        return HardeningCheck(
            check_id=SH_003_RDP,
            label="RDP deaktiviert",
            passed=passed,
            severity=severity,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # SH-004 — Automatische Updates
    # ------------------------------------------------------------------

    def check_auto_update(self, *, now: datetime | None = None) -> HardeningCheck:
        """SH-004: Windows-Update funktionsfaehig, geschichtet).

        Statt nur die AUOptions-Policy zu lesen (die auf einem unverwalteten
        Einzelplatz GAR NICHT existiert -> frueher endlos „nicht messbar")
        prueft SH-004 jetzt zwei admin-frei lesbare Registry-Signale:

        1. **Dienst-Start** (``wuauserv\\Start``): Ist der Windows-Update-Dienst
           deaktiviert (Start=4), kommen ueberhaupt keine Updates an -> Verstoss.
        2. **Frische** (``Results\\Detect|Install\\LastSuccessTime``): Liegt die
           letzte ERFOLGREICHE Update-Suche laenger als
:data:`_MAX_SEARCH_AGE_DAYS` zurueck (oder ist keine verzeichnet),
           steht der Update-Mechanismus -> Verstoss.

        **Overlay** (verwaltete/WSUS-Umgebung): Ist ``AUOptions`` gesetzt und
        bedeutet „kein Auto" ({1, 2}), zaehlt das zusaetzlich als Verstoss.

        Der Dienst-Start-Key existiert auf JEDEM Windows -> SH-004 ist damit
        praktisch immer messbar und laeuft nicht mehr in den NEEDS_ADMIN ->
        NOT_APPLICABLE-Pfad. Nur wenn KEIN Signal lesbar ist (sehr
        ungewoehnlich), bleibt der Check ehrlich ``measurable=False``
        (NOT_APPLICABLE — Adminrechte wuerden die world-readable Keys auch
        nicht aendern, also kein Recheck-Karussell).

        Args:
            now: Aktueller Zeitpunkt (UTC-aware). ``None`` (Default, Produktion)
                liest ``datetime.now(UTC)``; Tests injizieren einen festen Wert
                fuer deterministische Frische-Grenzen.
        """
        service_start = self._probe.read_registry_value(
            HIVE_HKLM, _WUAUSERV_START_KEY, _WUAUSERV_START_VALUE
        )
        au_options = self._probe.read_registry_value(
            HIVE_HKLM, _WU_AUTO_UPDATE_KEY, _WU_AU_OPTIONS_VALUE
        )
        last_search = self._probe.read_registry_value(
            HIVE_HKLM, _WU_RESULTS_DETECT_KEY, _WU_LAST_SUCCESS_VALUE
        )
        last_install = self._probe.read_registry_value(
            HIVE_HKLM, _WU_RESULTS_INSTALL_KEY, _WU_LAST_SUCCESS_VALUE
        )

        # Kein einziges Signal lesbar -> ehrlich nicht messbar (terminal n/a,
        # damit das Mess-Banner nicht endlos „Mit Admin messen" fordert).
        if (
            service_start is None
            and au_options is None
            and last_search is None
            and last_install is None
        ):
            return self._registry_missing(
                SH_004_AUTO_UPDATE,
                "Windows-Update funktionsfaehig",
                Severity.HIGH,
                _WU_LAST_SUCCESS_VALUE,
                reason=UnmeasuredReason.NOT_APPLICABLE,
            )

        passed, detail = _classify_auto_update(
            service_start=service_start,
            au_options=au_options,
            last_search=last_search,
            last_install=last_install,
            now=now if now is not None else datetime.now(UTC),
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        return HardeningCheck(
            check_id=SH_004_AUTO_UPDATE,
            label="Windows-Update funktionsfaehig",
            passed=passed,
            severity=Severity.HIGH,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # SH-005 — SMBv1
    # ------------------------------------------------------------------

    def check_smbv1(self) -> HardeningCheck:
        """SH-005: SMBv1 deaktiviert (EnableSMB1Protocol = False)."""
        script = "(Get-SmbServerConfiguration).EnableSMB1Protocol"
        result = self._probe.run_powershell(script)
        if not result.success:
            return self._probe_failed(
                SH_005_SMBV1,
                "SMBv1 deaktiviert",
                Severity.CRITICAL,
                result.error,
            )
        # Output ist "True" oder "False" (PowerShell-Boolean-stringify)
        output = result.stdout.strip().lower()
        passed = output == "false"
        return HardeningCheck(
            check_id=SH_005_SMBV1,
            label="SMBv1 deaktiviert",
            passed=passed,
            severity=Severity.CRITICAL,
            detail=f"EnableSMB1Protocol = {output or '(leer)'}",
        )

    # ------------------------------------------------------------------
    # SH-006 — Gastkonto
    # ------------------------------------------------------------------

    def check_guest_account(self) -> HardeningCheck:
        """SH-006: Gastkonto deaktiviert.

        Primaer locale-frei via ``Get-LocalUser`` (Gastkonto ueber die
        well-known SID ``*-501``, boolean ``.Enabled`` Phase 2).
        Fallback: ``net user`` (DE/EN geparst); sonst measurable=False/PARSE_FAILED.
        """
        ps = self._probe.run_powershell(_PS_GUEST_ACCOUNT)
        token = ps.stdout.strip().lower() if ps.success else ""
        if token in ("disabled", "absent"):
            return HardeningCheck(
                check_id=SH_006_GUEST_ACCOUNT,
                label="Gastkonto deaktiviert",
                passed=True,
                severity=Severity.MEDIUM,
                detail=(
                    "Kein Gastkonto vorhanden"
                    if token == "absent"
                    else "Gastkonto ist deaktiviert"
                ),
            )
        if token == "enabled":
            return HardeningCheck(
                check_id=SH_006_GUEST_ACCOUNT,
                label="Gastkonto deaktiviert",
                passed=False,
                severity=Severity.MEDIUM,
                detail="Gastkonto ist AKTIV — Empfehlung: deaktivieren",
            )
        # Fallback: net user (DE/EN).
        result = self._probe.run_command("net", ["user", "Guest"])
        if not result.success:
            # Auf manchen Systemen heisst der User "Gast" — eigener Fallback.
            result_de = self._probe.run_command("net", ["user", "Gast"])
            if not result_de.success:
                return self._probe_failed(
                    SH_006_GUEST_ACCOUNT,
                    "Gastkonto deaktiviert",
                    Severity.MEDIUM,
                    f"{result.error}; {result_de.error}",
                )
            result = result_de

        lower = result.stdout.lower()
        # Whitespace-/Label-tolerant: EN "Account active No" / DE "Konto aktiv Nein".
        deactivated = re.search(r"(account active|konto aktiv)\s+(no|nein)\b", lower)
        active = re.search(r"(account active|konto aktiv)\s+(yes|ja)\b", lower)
        if deactivated:
            return HardeningCheck(
                check_id=SH_006_GUEST_ACCOUNT,
                label="Gastkonto deaktiviert",
                passed=True,
                severity=Severity.MEDIUM,
                detail="Gastkonto ist deaktiviert",
            )
        if active:
            return HardeningCheck(
                check_id=SH_006_GUEST_ACCOUNT,
                label="Gastkonto deaktiviert",
                passed=False,
                severity=Severity.MEDIUM,
                detail="Gastkonto ist AKTIV — Empfehlung: deaktivieren",
            )
        # net user lief, aber der Aktiv-Status liess sich NICHT auslesen (z.B.
        # nicht-DE/EN-Locale + Get-LocalUser nicht verfuegbar) -> NICHT als
        # Verstoss werten (kein Fehl-MEDIUM). measurable=False.
        return HardeningCheck(
            check_id=SH_006_GUEST_ACCOUNT,
            label="Gastkonto deaktiviert",
            passed=False,
            severity=Severity.MEDIUM,
            detail=(
                "Gastkonto-Status nicht auslesbar (Spracheinstellung) "
                "— als nicht messbar gewertet"
            ),
            measurable=False,
            unmeasured_reason=UnmeasuredReason.PARSE_FAILED,
        )

    # ------------------------------------------------------------------
    # SH-007 — Passwort-Policy
    # ------------------------------------------------------------------

    def check_password_policy(self) -> HardeningCheck:
        """SH-007: Min. Passwort-Laenge >= 8.

        Methode: ``net accounts``. Output enthaelt
        ``"Minimum password length: 8"`` (en) oder
        ``"Mindestlaenge des Kennworts: 8"`` (de).
        """
        result = self._probe.run_command("net", ["accounts"])
        if not result.success:
            return self._probe_failed(
                SH_007_PASSWORD_POLICY,
                f"Passwort-Min-Laenge >= {_MIN_PASSWORD_LENGTH}",
                Severity.HIGH,
                result.error,
            )

        min_len = _parse_password_min_length(result.stdout)
        if min_len is None:
            # Ausgabe nicht interpretierbar (z.B. fremde Locale) -> nicht
            # messbar, NICHT als Verstoss werten/026). Reason analog zu
            # SH-001/006/009 (Befehl lief, Ausgabe nicht parsebar).
            return HardeningCheck(
                check_id=SH_007_PASSWORD_POLICY,
                label=f"Passwort-Min-Laenge >= {_MIN_PASSWORD_LENGTH}",
                passed=False,
                severity=Severity.HIGH,
                detail="Nicht messbar: Min-Laenge im net-accounts-Output nicht interpretierbar (Sprache?)",
                measurable=False,
                unmeasured_reason=UnmeasuredReason.PARSE_FAILED,
            )
        passed = min_len >= _MIN_PASSWORD_LENGTH
        return HardeningCheck(
            check_id=SH_007_PASSWORD_POLICY,
            label=f"Passwort-Min-Laenge >= {_MIN_PASSWORD_LENGTH}",
            passed=passed,
            severity=Severity.HIGH,
            detail=f"Aktuelle Min-Laenge: {min_len}",
        )

    # ------------------------------------------------------------------
    # SH-008 — Autorun
    # ------------------------------------------------------------------

    def check_autorun(self) -> HardeningCheck:
        """SH-008: Autorun deaktiviert (NoDriveTypeAutoRun = 0xFF = 255).

        Wert 0xFF (=255) blockt Autorun fuer alle Drive-Types. Wert 0
        oder fehlend = Autorun aktiv.
        """
        value = self._probe.read_registry_value(
            HIVE_HKLM,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            "NoDriveTypeAutoRun",
        )
        if value is None:
            return HardeningCheck(
                check_id=SH_008_AUTORUN,
                label="Autorun deaktiviert",
                passed=False,
                severity=Severity.MEDIUM,
                detail="NoDriveTypeAutoRun-Wert fehlt — Default = Autorun aktiv",
            )
        try:
            int_value = int(value)
        except ValueError:
            # Wert vorhanden, aber nicht interpretierbar -> nicht messbar
            #. Der FEHLENDE Wert oben bleibt dagegen ein echtes
            # Finding (Autorun per Default aktiv).
            return HardeningCheck(
                check_id=SH_008_AUTORUN,
                label="Autorun deaktiviert",
                passed=False,
                severity=Severity.MEDIUM,
                detail=f"Nicht messbar: NoDriveTypeAutoRun nicht numerisch: {value!r}",
                measurable=False,
                unmeasured_reason=UnmeasuredReason.PARSE_FAILED,
            )
        passed = int_value == 255
        return HardeningCheck(
            check_id=SH_008_AUTORUN,
            label="Autorun deaktiviert",
            passed=passed,
            severity=Severity.MEDIUM,
            detail=f"NoDriveTypeAutoRun = {int_value} (255 = alle Typen geblockt)",
        )

    # ------------------------------------------------------------------
    # SH-009 — Lokale Admins
    # ------------------------------------------------------------------

    def check_local_admins(self) -> HardeningCheck:
        """SH-009: Anzahl lokaler Admins <= 2.

        Primaer locale-frei via ``Get-LocalGroupMember`` ueber die Gruppen-SID
        ``S-1-5-32-544`` (Administratoren — sprachneutral, kein Tabellen-Parsing;
 Phase 2). Fallback: ``net localgroup`` (DE/EN-Tabelle geparst,
        robust gegen den Get-LocalGroupMember-Domain-SID-Bug); sonst
        measurable=False/PARSE_FAILED.
        """
        ps = self._probe.run_powershell(_PS_LOCAL_ADMINS_COUNT)
        if ps.success and ps.stdout.strip().isdigit():
            admin_count = int(ps.stdout.strip())
            return HardeningCheck(
                check_id=SH_009_LOCAL_ADMINS,
                label=f"Lokale Admins <= {_MAX_LOCAL_ADMINS}",
                passed=admin_count <= _MAX_LOCAL_ADMINS,
                severity=Severity.HIGH,
                detail=f"{admin_count} Admin(s) gefunden (Get-LocalGroupMember)",
            )
        # Fallback: net localgroup (DE/EN).
        result = self._probe.run_command("net", ["localgroup", "Administrators"])
        if not result.success:
            result_de = self._probe.run_command(
                "net", ["localgroup", "Administratoren"]
            )
            if not result_de.success:
                return self._probe_failed(
                    SH_009_LOCAL_ADMINS,
                    f"Lokale Admins <= {_MAX_LOCAL_ADMINS}",
                    Severity.HIGH,
                    f"{result.error}; {result_de.error}",
                )
            result = result_de

        admin_count = _parse_localgroup_member_count(result.stdout)
        if admin_count is None:
            # Ausgabe nicht interpretierbar (z.B. fremde Locale) -> nicht
            # messbar, NICHT als Verstoss werten/026).
            return HardeningCheck(
                check_id=SH_009_LOCAL_ADMINS,
                label=f"Lokale Admins <= {_MAX_LOCAL_ADMINS}",
                passed=False,
                severity=Severity.HIGH,
                detail="Nicht messbar: Member-Anzahl nicht interpretierbar (Sprache?)",
                measurable=False,
                unmeasured_reason=UnmeasuredReason.PARSE_FAILED,
            )
        passed = admin_count <= _MAX_LOCAL_ADMINS
        return HardeningCheck(
            check_id=SH_009_LOCAL_ADMINS,
            label=f"Lokale Admins <= {_MAX_LOCAL_ADMINS}",
            passed=passed,
            severity=Severity.HIGH,
            detail=f"{admin_count} Admin(s) gefunden",
        )

    # ------------------------------------------------------------------
    # SH-010 — BitLocker
    # ------------------------------------------------------------------

    def check_bitlocker(self) -> HardeningCheck:
        """SH-010: BitLocker aktiv auf Systemlaufwerk C:.

        **Edition-Gate zuerst:** Auf Home/Core-Editionen gibt es BitLocker
        strukturell NICHT -> sofort ``NOT_APPLICABLE`` (score-neutral). Frueher
        lief die Probe dort ins Leere und lieferte ``WBEM_E_ACCESS_DENIED``
        (0x80041003), was faelschlich als ``NEEDS_ADMIN`` galt -> Endlos-"Mit
        Admin messen", das auch elevated nie aufgeht. Die Edition ist locale-frei
        und OHNE Admin aus der Registry lesbar.

        Auf BitLocker-faehigen Editionen (oder wenn die Edition nicht ermittelbar
        ist): primaer locale-frei via ``Get-BitLockerVolume`` (``.ProtectionStatus``
        Enum On/Off Phase 2), Fallback ``manage-bde -status`` (DE/EN-Text);
        schlaegt auch der fehl -> measurable=False/NEEDS_ADMIN.
        """
        if self._bitlocker_capable_edition() is False:
            return HardeningCheck(
                check_id=SH_010_BITLOCKER,
                label="BitLocker aktiv auf C:",
                passed=False,
                severity=Severity.MEDIUM,
                detail=(
                    "BitLocker ist auf dieser Windows-Edition (Home) nicht "
                    "verfuegbar — nicht zutreffend"
                ),
                measurable=False,
                unmeasured_reason=UnmeasuredReason.NOT_APPLICABLE,
            )
        ps = self._probe.run_powershell(_PS_BITLOCKER_C)
        if ps.success:
            status = ps.stdout.strip().lower()
            if status in ("on", "off"):
                return HardeningCheck(
                    check_id=SH_010_BITLOCKER,
                    label="BitLocker aktiv auf C:",
                    passed=status == "on",
                    severity=Severity.MEDIUM,
                    detail=(
                        "C:-Laufwerk ist BitLocker-geschuetzt (Get-BitLockerVolume)"
                        if status == "on"
                        else "BitLocker auf C: NICHT aktiv (Get-BitLockerVolume)"
                    ),
                )
        # Fallback: manage-bde (DE/EN-Text).
        result = self._probe.run_command("manage-bde", ["-status", "C:"])
        if not result.success:
            return self._probe_failed(
                SH_010_BITLOCKER,
                "BitLocker aktiv auf C:",
                Severity.MEDIUM,
                result.error,
            )
        lower = result.stdout.lower()
        if "protection on" in lower or "schutz aktiviert" in lower:
            return HardeningCheck(
                check_id=SH_010_BITLOCKER,
                label="BitLocker aktiv auf C:",
                passed=True,
                severity=Severity.MEDIUM,
                detail="C:-Laufwerk ist BitLocker-geschuetzt",
            )
        if "protection off" in lower or "schutz deaktiviert" in lower:
            return HardeningCheck(
                check_id=SH_010_BITLOCKER,
                label="BitLocker aktiv auf C:",
                passed=False,
                severity=Severity.MEDIUM,
                detail="BitLocker auf C: NICHT aktiv",
            )
        # manage-bde lief, aber Status nicht eindeutig (z.B. Nicht-DE/EN-Locale) ->
        # NICHT als Verstoss werten (kein erfundenes MEDIUM/Cap). measurable=False
        # (gleiche 3-Zustands-Logik wie SH-001/006/009).
        return HardeningCheck(
            check_id=SH_010_BITLOCKER,
            label="BitLocker aktiv auf C:",
            passed=False,
            severity=Severity.MEDIUM,
            detail=(
                "BitLocker-Status nicht eindeutig auslesbar (Spracheinstellung) "
                "— als nicht messbar gewertet"
            ),
            measurable=False,
            unmeasured_reason=UnmeasuredReason.PARSE_FAILED,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _bitlocker_capable_edition(self) -> bool | None:
        """Ob die Windows-Edition BitLocker ueberhaupt unterstuetzt (SH-010).

        BitLocker fehlt strukturell auf der Home-Familie (``EditionID`` beginnt
        mit ``"Core"``: Core, CoreN, CoreSingleLanguage, CoreCountrySpecific).
        Pro/Enterprise/Education/Workstation unterstuetzen es. Locale-frei und
        ohne Adminrechte aus der Registry lesbar.

        Returns:
            ``True`` bei BitLocker-faehiger Edition, ``False`` bei Home/Core,
            ``None`` wenn die Edition nicht ermittelbar ist (dann NICHT vorschnell
            n/a — normal weiterpruefen).
        """
        ps = self._probe.run_powershell(_PS_EDITION_ID)
        if not ps.success:
            return None
        edition = ps.stdout.strip()
        if not edition:
            return None
        return not edition.lower().startswith("core")

    @staticmethod
    def _probe_failed(
        check_id: str,
        label: str,
        severity: Severity,
        error: str,
        *,
        reason: UnmeasuredReason = UnmeasuredReason.NEEDS_ADMIN,
    ) -> HardeningCheck:
        """Baut einen HardeningCheck fuer ``passed=False`` bei Probe-Fehler.

        Wird verwendet, wenn der Probe-Aufruf selbst nicht ermitteln konnte
        (Timeout, Permission/Access-Denied, Tool nicht installiert z.B.
        manage-bde auf Home-Editionen).: Das ist NICHT "durchgefallen",
        sondern **nicht messbar** (``measurable=False``) — der Check zaehlt dann
        weder im Score noch als Verstoss noch als Finding. ``log.debug`` statt
        ``warning``: ein nicht-messbarer Check ohne Admin ist kein Alarm.

        ``reason`` kategorisiert die Unmessbarkeit (Default
        ``NEEDS_ADMIN`` — der haeufigste, via Admin-Recheck behebbare Fall).
        Caller setzen ``NOT_APPLICABLE`` (Feature/Tool strukturell nicht da).
        """
        log.debug("Check %s nicht messbar (%s): %s", check_id, reason.value, error)
        return HardeningCheck(
            check_id=check_id,
            label=label,
            passed=False,
            severity=severity,
            detail=f"Nicht messbar: {error} (ggf. mit Admin-Rechten erneut pruefen)",
            measurable=False,
            unmeasured_reason=reason,
        )

    @staticmethod
    def _registry_missing(
        check_id: str,
        label: str,
        severity: Severity,
        value_name: str,
        *,
        reason: UnmeasuredReason = UnmeasuredReason.NEEDS_ADMIN,
    ) -> HardeningCheck:
        """Baut einen HardeningCheck fuer nicht lesbaren Registry-Wert.

        ``read_registry_value`` liefert ``None`` sowohl bei fehlendem
        Wert als auch bei Permission-Denied — beide Faelle sind "Zustand nicht
        ermittelbar". Statt das als Verstoss (passed=False) zu werten, gilt der
        Check als **nicht messbar** (``measurable=False``): er zaehlt nicht in
        Score/Caps/Findings. Das verhindert v.a. das frueher faelschliche
        kritische "RDP aktiviert", wenn der Wert nur nicht gelesen werden konnte.

        ``reason`` Default ``NEEDS_ADMIN`` — ein None-Registry-Read ist
        ueberwiegend ein Rechtemangel und via Admin-Recheck behebbar. Ob der Key
        TROTZ Admin fehlt (echtes ``NOT_APPLICABLE``, z.B. AUOptions ohne WSUS),
        klaert erst der elevierte Recheck (Phase 4).
        """
        return HardeningCheck(
            check_id=check_id,
            label=label,
            passed=False,
            severity=severity,
            detail=f"Nicht messbar: Registry-Wert {value_name} nicht lesbar",
            measurable=False,
            unmeasured_reason=reason,
        )


# ---------------------------------------------------------------------------
# Headless Baseline-Factory C0b)
# ---------------------------------------------------------------------------


def run_hardening_baseline_scan(
    probe: IHardeningProbe | None = None,
) -> ScanResult | None:
    """Fuehrt einen frischen Hardening-Scan aus und buendelt ihn in ein ScanResult.

    Headless + Qt-frei C0b). Verdrahtet den
:class:`WindowsHardeningScanner` mit dem Production-Probe und liefert ein
    minimales:class:`ScanResult`, das ausschliesslich die frischen
    ``hardening_checks`` (Kategorie E) traegt. Damit kann
:meth:`tools.security_scoring.application.scoring_service.ScoringService.compute_hardening_score`
    den Category-E-Beitrag + die Hard-Caps 3/4 (RDP/Firewall) ohne GUI und
    ohne den vollen System-Scan (Software-Inventar etc.) berechnen.

    Erlaubt Cross-Tool-Aufrufern (security_scoring) den Scan zu beziehen,
    ohne ``data/`` direkt zu importieren — analog
:func:`tools.system_scanner.application.scan_history_use_case.create_default_scan_history_use_case`.

    Non-Windows Phase 3.3): Der:class:`WindowsHardeningProbe`
    meldet dort ``is_available == False``. Wuerde man trotzdem scannen,
    waere jeder Check ein Probe-Fehler (``passed=False``) — ein irrefuehrend
    schlechtes, teils durch Caps 3/4 gedeckeltes Ergebnis. Deshalb liefert
    die Funktion dann ``None``; der Aufrufer berechnet den Score wie bisher
    ohne Kategorie E (``scan_result=None``).

    Args:
        probe: Optionaler:class:`IHardeningProbe`. ``None`` (Default) baut
            den Production-:class:`WindowsHardeningProbe`. Tests injizieren
            einen:class:`MockHardeningProbe` (auch fuer den Non-Windows-
            Pfad via ``available=False``).

    Returns:
        Ein:class:`ScanResult` mit den 10 ``hardening_checks``, oder
        ``None`` wenn der Probe nicht verfuegbar ist (Non-Windows).
    """
    if probe is None:
        from core.probes.windows_hardening_probe import (  # noqa: PLC0415
            WindowsHardeningProbe,
        )

        probe = WindowsHardeningProbe()

    if not probe.is_available():
        log.info(
            "Hardening-Baseline uebersprungen — Probe nicht verfuegbar "
            "(Non-Windows). Kategorie E bleibt ohne Daten."
        )
        return None

    start = time.monotonic()
    checks = WindowsHardeningScanner(probe).scan_all()
    duration = time.monotonic() - start

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=checks,
        scan_duration_s=round(duration, 3),
    )


# ---------------------------------------------------------------------------
# Parser-Helpers (pure)
# ---------------------------------------------------------------------------


def _parse_wu_timestamp(raw: str | None) -> datetime | None:
    """Parst einen Windows-Update ``LastSuccessTime``-Wert (SH-004).

    Der Update-Agent schreibt locale-frei im Format ``"%Y-%m-%d %H:%M:%S"`` in
    UTC. Das Ergebnis ist UTC-aware, damit die Altersberechnung gegen
    ``datetime.now(UTC)`` sauber ist.

    Args:
        raw: Roher Registry-Wert oder ``None``.

    Returns:
        UTC-aware:class:`datetime`, oder ``None`` wenn leer/unparsebar.
    """
    if not raw:
        return None
    try:
        return datetime.strptime(raw.strip(), _WU_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def _age_phrase(days: int) -> str:
    """Menschenlesbare Alters-Phrase fuer den SH-004-Detailtext (Sie-Form)."""
    if days <= 0:
        return "heute"
    if days == 1:
        return "vor 1 Tag"
    return f"vor {days} Tagen"


def _classify_auto_update(
    *,
    service_start: str | None,
    au_options: str | None,
    last_search: str | None,
    last_install: str | None,
    now: datetime,
    max_search_age_days: int,
) -> tuple[bool, str]:
    """Geschichtete SH-004-Entscheidung (pure).

    Reihenfolge nach Grundsaetzlichkeit der Ursache:
    1. Update-Dienst deaktiviert (Start=4) -> Verstoss (Root-Cause).
    2. AUOptions-Policy „kein Auto" ({1, 2}) -> Verstoss (managed/WSUS-Overlay).
    3. Letzte erfolgreiche Suche aelter als ``max_search_age_days``, keine
       verzeichnet ODER unplausibel (Zukunft/1601-Sentinel) -> Verstoss
       (Mechanismus steht / lange offline / kein verlaesslicher Beweis).
    Sonst: bestanden, mit letzter Suche + Installation als Kontext.

    Args:
        service_start: ``wuauserv\\Start`` als String (REG_DWORD) oder ``None``.
        au_options: ``AUOptions`` oder ``None``.
        last_search: ``Results\\Detect\\LastSuccessTime`` oder ``None``.
        last_install: ``Results\\Install\\LastSuccessTime`` oder ``None``.
        now: Aktueller Zeitpunkt (UTC-aware) — injiziert fuer Testbarkeit.
        max_search_age_days: Schwelle in Tagen.

    Returns:
        Tupel ``(passed, detail)``.
    """
    if service_start == _SERVICE_START_DISABLED:
        return False, (
            "Windows-Update-Dienst ist deaktiviert — Updates kommen nicht an. "
            "Aktivieren Sie den Dienst (Starttyp Automatisch oder Manuell)."
        )

    if au_options in _AU_OPTIONS_NO_AUTO:
        return False, (
            f"Automatische Updates sind per Richtlinie deaktiviert "
            f"(AUOptions={au_options}). Aktivieren Sie automatische Updates."
        )

    search_dt = _parse_wu_timestamp(last_search)
    install_dt = _parse_wu_timestamp(last_install)

    # ``.days`` zaehlt bewusst GANZE Tage (Tages-Granularitaet ist gewollt).
    search_age = None if search_dt is None else (now - search_dt).days
    # Kein Datum, Zukunft (search_age < 0 durch Uhr-Skew/Manipulation) oder
    # absurd alt (1601-Sentinel > ~10 Jahre) -> kein Beweis einer erfolgreichen
    # Suche -> fail-closed, ohne den unplausiblen Wert anzuzeigen.
    if search_age is None or not 0 <= search_age <= _PLAUSIBLE_MAX_SEARCH_AGE_DAYS:
        return False, (
            "Keine verlaessliche erfolgreiche Update-Suche verzeichnet — "
            "pruefen Sie, ob Windows-Update funktioniert."
        )

    if search_age > max_search_age_days:
        return False, (
            f"Seit {search_age} Tagen keine erfolgreiche Update-Suche "
            f"(zuletzt {search_dt.date().isoformat()}). Der Update-Mechanismus "
            f"steht oder die Maschine war lange offline."
        )

    install_part = (
        f", letzte Installation am {install_dt.date().isoformat()}"
        if install_dt is not None
        else ""
    )
    return True, (
        f"Letzte erfolgreiche Update-Suche {_age_phrase(search_age)} "
        f"({search_dt.date().isoformat()}){install_part}. Update-Dienst aktiv."
    )


def _parse_rdp_port_state(result: ProbeResult) -> tuple[bool | None, bool | None]:
    """Parst die:data:`_PS_RDP_PORT_STATE`-Ausgabe in (listening, established).

    Erwartet ``"<listen>,<established>"`` (zwei Zahlen, SH-003/). Schlaegt
    die Probe fehl oder ist die Ausgabe nicht interpretierbar, liefert die
    Funktion ``(None, None)`` — der Aufrufer behandelt „unbekannt" fail-closed
    (kein Beweis aktiver Nutzung -> aktiviertes RDP zaehlt als unnoetige
    Exposition, nicht als bewusst genutzt).

    Args:
        result: ProbeResult des PowerShell-Aufrufs.

    Returns:
        ``(listening, established)`` als Bool, oder ``(None, None)`` bei
        Fehler/unparsebarer Ausgabe.
    """
    if not result.success:
        return None, None
    parts = result.stdout.strip().split(",")
    if len(parts) != 2:
        return None, None
    try:
        listen = int(parts[0].strip())
        established = int(parts[1].strip())
    except ValueError:
        return None, None
    return listen > 0, established > 0


def _classify_rdp(
    *,
    fdeny: str | None,
    service_start: str | None,
    listening: bool | None,
    established: bool | None,
) -> tuple[bool, Severity, str] | None:
    """Geschichtete SH-003-Entscheidung (pure).

    Kern-Prinzip: **der LISTENER ist die echte Angriffsflaeche**, nicht das
    Policy-Bit. Eine ``fDenyTSConnections=0``-Richtlinie ohne lauschenden Dienst
    ist KEINE aktive Exposition (Patrick 2026-06-26: „wenn es kein RDP gibt, muss
    der Cap weg"). ``established`` wird ausschliesslich UNTER einem echten Listener
    ausgewertet und zaehlt nur REMOTE-Sitzungen (Loopback ist in der Probe
    herausgefiltert) — ein lokaler Self-Connect kann so den Score nicht schoenen.

    Reihenfolge:

    1. RDP nachweislich AUS (Policy ``deny`` ODER Dienst ``Start=4``) -> bestanden.
       Authoritativ: bei deaktiviertem RDP nimmt TermService den Port nicht an;
       etwaige Verbindungen auf 3389 sind Fremd-Dienste, kein RDP (verhindert den
       False-Positive auf einer gehaerteten Maschine).
    2. LISTENER vorhanden (Port 3389 hoert) -> echte Angriffsflaeche:
       * aktive REMOTE-Sitzung -> ``HIGH`` („absichern"), KEIN Hard-Cap.
       * keine Remote-Sitzung -> ``CRITICAL`` („abschalten", loest Cap 3 aus).
    3. Listener nachweislich NICHT vorhanden (``listening=False``) -> kein realer
       Fernzugriff -> bestanden, KEIN Cap, unabhaengig vom Policy-Bit.
    4. Listener-Status unbekannt (Probe fehlgeschlagen) UND Policy nicht ``deny``
       -> ``None`` (nicht messbar; kein fail-closed-Cap auf nicht erreichbarem RDP).

    Args:
        fdeny: ``fDenyTSConnections`` als String oder ``None``.
        service_start: ``TermService\\Start`` (REG_DWORD) als String oder ``None``.
        listening: True wenn Port 3389 hoert, False wenn nachweislich nicht,
            ``None`` wenn die Probe fehlschlug.
        established: True bei aktiver REMOTE-Sitzung auf 3389 (Loopback gefiltert),
            sonst False/``None``. Nur unter ``listening=True`` relevant.

    Returns:
        Tupel ``(passed, severity, detail)`` oder ``None`` wenn nicht messbar.
    """
    # 1. RDP nachweislich aus -> bestanden (autoritativ vor Netz-Signalen).
    if fdeny == "1":
        return (
            True,
            Severity.CRITICAL,
            "RDP ist deaktiviert (fDenyTSConnections=1) — kein Fernzugriff moeglich.",
        )
    if service_start == _SERVICE_START_DISABLED:
        return (
            True,
            Severity.CRITICAL,
            "RDP-Dienst (TermService) ist deaktiviert — kein Fernzugriff moeglich.",
        )
    # 2. Listener vorhanden -> echte Angriffsflaeche; Remote-Sitzung entscheidet
    # HIGH (genutzt, kein Cap) vs CRITICAL (erreichbar-ungenutzt, Cap 3).
    if listening is True:
        if established is True:
            return (
                False,
                Severity.HIGH,
                (
                    "RDP wird aktuell aktiv genutzt (bestehende Remote-Sitzung "
                    "auf Port 3389). Da Sie Fernzugriff brauchen: unbedingt "
                    "absichern — Network Level Authentication (NLA), starke "
                    "Passwoerter mit Kontosperrung, Zugriff nur ueber VPN oder "
                    "Firewall-Freigabe, nicht benoetigte Konten ausschliessen."
                ),
            )
        return (
            False,
            Severity.CRITICAL,
            (
                "Der RDP-Dienst lauscht auf Port 3389 (Fernzugriff aktiv), aber "
                "es besteht keine aktive Sitzung — der Zugang wird offenbar nicht "
                "genutzt. Ob er von aussen erreichbar ist, haengt zusaetzlich von "
                "Ihrer Firewall ab. Offenes, ungenutztes RDP ist eine unnoetige "
                "Angriffsflaeche und ein Haupt-Einfallstor fuer Ransomware. Falls "
                "nicht benoetigt: abschalten."
            ),
        )
    # 3. Listener nachweislich weg -> kein realer Fernzugriff -> bestanden (kein
    # Cap), egal was die Policy sagt.
    if listening is False:
        if fdeny == "0":
            return (
                True,
                Severity.CRITICAL,
                (
                    "RDP ist per Richtlinie erlaubt (fDenyTSConnections=0), der "
                    "Dienst hoert aber nicht auf Port 3389 — kein aktiver "
                    "Fernzugriff. Zur Sicherheit koennen Sie RDP ganz deaktivieren."
                ),
            )
        return (
            True,
            Severity.CRITICAL,
            "Kein RDP-Listener auf Port 3389 — kein aktiver Fernzugriff.",
        )
    # 4. Listener-Status unbekannt (Probe fehlgeschlagen) UND Policy nicht „deny".
    return None


def _parse_password_min_length(net_accounts_output: str) -> int | None:
    """Extrahiert die Minimum-Passwort-Laenge aus ``net accounts``-Output.

    Englisch: ``"Minimum password length: 8"``
    Deutsch: ``"Mindestlaenge des Kennworts: 8"`` /
              ``"Minimale Kennwortlaenge: 8"``

    Returns:
        Die Mindestlaenge als int, oder ``None`` wenn nicht parsebar.
    """
    for line in net_accounts_output.splitlines():
        lower = line.lower().strip()
        if not lower:
            continue
        # Englische Variante
        if "minimum password length" in lower:
            return _last_int(line)
        # Deutsche Varianten
        if (
            "mindestlaenge des kennworts" in lower
            or "mindestlänge des kennworts" in lower
        ):
            return _last_int(line)
        if "minimale kennwortlaenge" in lower or "minimale kennwortlänge" in lower:
            return _last_int(line)
    return None


def _parse_localgroup_member_count(net_output: str) -> int | None:
    """Extrahiert die Anzahl der Members aus ``net localgroup``-Output.

    Output-Struktur (vereinfacht):

.. code-block:: text

        Alias name Administrators
        Comment Administrators have complete and unrestricted access...

        Members

        -------------------------------------------------------------------------------
        Administrator
        AnotherAdmin
        The command completed successfully.

    Wir zaehlen die Zeilen zwischen dem ``-----``-Trenner und dem
    Abschluss-Satz.

    Returns:
        Anzahl Members oder ``None`` wenn die Struktur nicht erkannt wird.
    """
    lines = net_output.splitlines()
    in_members_block = False
    count = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("---"):
            in_members_block = not in_members_block
            continue
        if not in_members_block:
            continue
        if not stripped:
            continue
        # Abschluss-Indikator
        lower = stripped.lower()
        if (
            "command completed" in lower
            or "befehl wurde erfolgreich" in lower
            or "der befehl wurde ausgef" in lower
        ):
            break
        count += 1
    if count == 0 and not in_members_block:
        # Trenner wurde nie gefunden — Output-Struktur unbekannt
        return None
    return count


def _last_int(line: str) -> int | None:
    """Extrahiert die letzte Ganzzahl aus einer Zeile."""
    parts = line.split()
    for part in reversed(parts):
        try:
            return int(part)
        except ValueError:
            continue
    return None
