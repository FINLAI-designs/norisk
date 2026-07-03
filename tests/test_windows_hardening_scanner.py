"""
test_windows_hardening_scanner — pytest-Tests fuer
``tools.system_scanner.application.windows_hardening_scanner``.

Phase 3.3 des Hardening-Score-Sprints §5). Pure Tests gegen
:class:`MockHardeningProbe` — laufen plattform-unabhaengig auf
Linux-CI.

Test-Bereiche pro Check:
    * Happy-Path: Probe liefert konformen Wert → passed=True
    * Negativ-Path: Probe liefert non-konformen Wert → passed=False
    * Probe-Fehler: success=False → passed=False mit Probe-Fehler-Detail
    * Registry-Wert fehlt → passed=False mit "fehlt"-Detail

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.probes.hardening_probe import HIVE_HKLM
from core.probes.mock_hardening_probe import MockHardeningProbe
from core.security.severity import Severity
from tools.system_scanner.application.windows_hardening_scanner import (
    _MAX_SEARCH_AGE_DAYS,
    _PS_BITLOCKER_C,
    _PS_EDITION_ID,
    _PS_FIREWALL_PROFILES,
    _PS_GUEST_ACCOUNT,
    _PS_LOCAL_ADMINS_COUNT,
    _PS_RDP_PORT_STATE,
    _RDP_DENY_VALUE,
    _RDP_TERMINAL_SERVER_KEY,
    _RDP_TERMSERVICE_KEY,
    _RDP_TERMSERVICE_START_VALUE,
    _WU_AUTO_UPDATE_KEY,
    _WU_LAST_SUCCESS_VALUE,
    _WU_RESULTS_DETECT_KEY,
    _WU_TIMESTAMP_FORMAT,
    _WUAUSERV_START_KEY,
    _WUAUSERV_START_VALUE,
    SH_001_FIREWALL,
    SH_002_UAC,
    SH_003_RDP,
    SH_004_AUTO_UPDATE,
    SH_005_SMBV1,
    SH_006_GUEST_ACCOUNT,
    SH_007_PASSWORD_POLICY,
    SH_008_AUTORUN,
    SH_009_LOCAL_ADMINS,
    SH_010_BITLOCKER,
    WindowsHardeningScanner,
    _age_phrase,
    _classify_auto_update,
    _classify_rdp,
    _parse_localgroup_member_count,
    _parse_password_min_length,
    _parse_rdp_port_state,
    _parse_wu_timestamp,
)
from tools.system_scanner.domain.enums import UnmeasuredReason

# ---------------------------------------------------------------------------
# Test-Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def probe() -> MockHardeningProbe:
    """Frische Mock-Probe pro Test."""
    return MockHardeningProbe()


@pytest.fixture
def scanner(probe: MockHardeningProbe) -> WindowsHardeningScanner:
    return WindowsHardeningScanner(probe)


# ===========================================================================
# SH-001 — Firewall
# ===========================================================================


class TestSh001Firewall:
    def test_all_profiles_on_passes(self, scanner, probe):
        # Englisches netsh-Output mit 3x "State... ON"
        probe.set_command_result(
            "netsh",
            ["advfirewall", "show", "allprofiles", "state"],
            stdout=(
                "Domain Profile Settings:\n"
                "State                                 ON\n"
                "Private Profile Settings:\n"
                "State                                 ON\n"
                "Public Profile Settings:\n"
                "State                                 ON\n"
            ),
        )
        check = scanner.check_firewall()
        assert check.check_id == SH_001_FIREWALL
        assert check.passed is True
        assert check.severity == Severity.CRITICAL

    def test_one_profile_off_fails(self, scanner, probe):
        probe.set_command_result(
            "netsh",
            ["advfirewall", "show", "allprofiles", "state"],
            stdout=(
                "Domain Profile Settings:\n"
                "State                                 OFF\n"
                "Private Profile Settings:\n"
                "State                                 ON\n"
                "Public Profile Settings:\n"
                "State                                 ON\n"
            ),
        )
        check = scanner.check_firewall()
        assert check.passed is False

    def test_probe_failure(self, scanner, probe):
        # Default (kein set_command_result) → success=False
        check = scanner.check_firewall()
        assert check.passed is False
        assert check.measurable is False  # Probe-Fehler = nicht messbar

    def test_unparseable_locale_is_not_measurable(self, scanner, probe):
        # Phase 0: netsh LAEUFT, aber nicht-DE/EN-Locale -> Status nicht parsebar.
        # Frueher: faelschlich passed=False -> Cap-4 Fehl-KRITISCH trotz aktiver
        # Firewall. Jetzt: measurable=False (kein erfundener Verstoss).
        probe.set_command_result(
            "netsh",
            ["advfirewall", "show", "allprofiles", "state"],
            stdout=(
                "Parametres du profil de domaine :\n"
                "Etat                                 Actif\n"
                "Parametres du profil prive :\n"
                "Etat                                 Actif\n"
                "Parametres du profil public :\n"
                "Etat                                 Actif\n"
            ),
        )
        check = scanner.check_firewall()
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.PARSE_FAILED
        assert "nicht messbar" in check.detail.lower()

    def test_german_netsh_ein_passes(self, scanner, probe):
        # deutsches Win11-netsh zeigt "Status EIN" (verifiziert auf der
        # echten Maschine), NICHT "ON". Frueher matchte die Regex nur "on" -> bei
        # ausgefallener Primaerprobe + DE-Locale faelschlich "nicht messbar"
        # (Firewall-False-Negative trotz aktiver Firewall).
        probe.set_command_result(
            "netsh",
            ["advfirewall", "show", "allprofiles", "state"],
            stdout=(
                "Domänenprofil-Einstellungen:\n"
                "Status                                   EIN\n"
                "Privates Profil-Einstellungen:\n"
                "Status                                   EIN\n"
                "Öffentliches Profil-Einstellungen:\n"
                "Status                                   EIN\n"
            ),
        )
        check = scanner.check_firewall()
        assert check.passed is True
        assert check.measurable is True

    def test_german_netsh_aus_fails(self, scanner, probe):
        # Ein deutsches "Status AUS" muss als deaktiviertes Profil erkannt werden.
        probe.set_command_result(
            "netsh",
            ["advfirewall", "show", "allprofiles", "state"],
            stdout=(
                "Domänenprofil-Einstellungen:\n"
                "Status                                   EIN\n"
                "Privates Profil-Einstellungen:\n"
                "Status                                   AUS\n"
                "Öffentliches Profil-Einstellungen:\n"
                "Status                                   EIN\n"
            ),
        )
        check = scanner.check_firewall()
        assert check.passed is False
        assert check.measurable is True

    # --- Phase 2: locale-freie PowerShell-Primaerabfrage ----------

    def test_powershell_primary_all_enabled_passes(self, scanner, probe):
        probe.set_powershell_result(_PS_FIREWALL_PROFILES, stdout="1,1,1")
        check = scanner.check_firewall()
        assert check.passed is True
        assert "Get-NetFirewallProfile" in check.detail

    def test_powershell_primary_one_disabled_fails(self, scanner, probe):
        probe.set_powershell_result(_PS_FIREWALL_PROFILES, stdout="1,0,1")
        check = scanner.check_firewall()
        assert check.passed is False
        assert check.measurable is True

    def test_probe_failure_reason_needs_admin(self, scanner, probe):
        # Weder PowerShell- noch netsh-Ergebnis -> nicht messbar/NEEDS_ADMIN.
        check = scanner.check_firewall()
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN

    def test_powershell_partial_count_no_false_pass(self, scanner, probe):
        # Review-P1: Teil-Messung ('1' = nur 1 Profil) darf NIE als
        # "alle Profile aktiv" (PASS) gewertet werden (false-secure auf CRITICAL).
        # Ohne netsh-Fallback -> faellt auf nicht messbar durch, KEIN PASS.
        for stdout in ("1", "1,1"):
            probe.set_powershell_result(_PS_FIREWALL_PROFILES, stdout=stdout)
            check = scanner.check_firewall()
            assert check.passed is False, stdout
            assert check.measurable is False, stdout

    def test_powershell_foreign_token_no_false_pass(self, scanner, probe):
        # '1,1,foo': Fremd-Token darf nicht still weggefiltert werden ->
        # kein 2-Profil-PASS. Faellt auf nicht messbar durch.
        probe.set_powershell_result(_PS_FIREWALL_PROFILES, stdout="1,1,foo")
        check = scanner.check_firewall()
        assert check.passed is False
        assert check.measurable is False


# ===========================================================================
# SH-002 — UAC
# ===========================================================================


class TestSh002Uac:
    _PATH = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"

    def test_enable_lua_1_passes(self, scanner, probe):
        probe.set_registry_value(HIVE_HKLM, self._PATH, "EnableLUA", "1")
        check = scanner.check_uac()
        assert check.check_id == SH_002_UAC
        assert check.passed is True
        assert check.severity == Severity.HIGH

    def test_enable_lua_0_fails(self, scanner, probe):
        probe.set_registry_value(HIVE_HKLM, self._PATH, "EnableLUA", "0")
        check = scanner.check_uac()
        assert check.passed is False
        assert "EnableLUA = 0" in check.detail

    def test_registry_value_missing(self, scanner):
        check = scanner.check_uac()
        # Registry nicht lesbar -> nicht messbar, NICHT Verstoss.
        assert check.measurable is False
        assert "nicht messbar" in check.detail.lower()


# ===========================================================================
# SH-003 — RDP
# ===========================================================================


class TestSh003Rdp:
    """SH-003 ueber den Scanner (Mock-Probe verdrahtet)."""

    def _set_port_state(self, probe, listen: int, established: int) -> None:
        probe.set_powershell_result(
            _PS_RDP_PORT_STATE, stdout=f"{listen},{established}"
        )

    def test_rdp_disabled_passes(self, scanner, probe):
        # fDenyTSConnections = 1 → "deny RDP" → konform (kein Listener noetig)
        probe.set_registry_value(
            HIVE_HKLM, _RDP_TERMINAL_SERVER_KEY, _RDP_DENY_VALUE, "1"
        )
        check = scanner.check_rdp()
        assert check.check_id == SH_003_RDP
        assert check.passed is True

    def test_rdp_service_disabled_passes(self, scanner, probe):
        # Dienst deaktiviert (Start=4) -> RDP aus, auch ohne fDeny-Wert.
        probe.set_registry_value(
            HIVE_HKLM, _RDP_TERMSERVICE_KEY, _RDP_TERMSERVICE_START_VALUE, "4"
        )
        check = scanner.check_rdp()
        assert check.passed is True

    def test_rdp_in_use_is_high_finding_not_capped(self, scanner, probe):
        # Aktivierte UND genutzte Sitzung (Established) -> HIGH, kein Cap.
        probe.set_registry_value(
            HIVE_HKLM, _RDP_TERMINAL_SERVER_KEY, _RDP_DENY_VALUE, "0"
        )
        self._set_port_state(probe, listen=1, established=1)
        check = scanner.check_rdp()
        assert check.passed is False
        assert check.severity == Severity.HIGH
        assert "absichern" in check.detail.lower()

    def test_rdp_reachable_but_unused_is_critical(self, scanner, probe):
        # Erreichbar (Listen), aber keine Sitzung -> unnoetige Exposition.
        probe.set_registry_value(
            HIVE_HKLM, _RDP_TERMINAL_SERVER_KEY, _RDP_DENY_VALUE, "0"
        )
        self._set_port_state(probe, listen=1, established=0)
        check = scanner.check_rdp()
        assert check.passed is False
        assert check.severity == Severity.CRITICAL
        assert "abschalten" in check.detail.lower()

    def test_rdp_enabled_but_not_reachable_passes_no_cap(self, scanner, probe):
        # Policy erlaubt RDP, aber kein Listener -> kein realer Fernzugriff ->
        # bestanden, KEIN Cap (Patrick 2026-06-26: „kein RDP -> kein Cap").
        probe.set_registry_value(
            HIVE_HKLM, _RDP_TERMINAL_SERVER_KEY, _RDP_DENY_VALUE, "0"
        )
        self._set_port_state(probe, listen=0, established=0)
        check = scanner.check_rdp()
        assert check.passed is True

    def test_policy_deny_wins_over_session(self, scanner, probe):
        # fDeny=1 ist autoritativ: eine Rest-/Fremdverbindung auf 3389 macht den
        # gehaerteten Host NICHT zu einem Befund (Review, False-Positive-Fix).
        probe.set_registry_value(
            HIVE_HKLM, _RDP_TERMINAL_SERVER_KEY, _RDP_DENY_VALUE, "1"
        )
        self._set_port_state(probe, listen=1, established=1)
        check = scanner.check_rdp()
        assert check.passed is True

    def test_unreadable_config_and_probe_is_not_measurable(self, scanner):
        # Weder Registry noch Listener-Probe verfuegbar -> ehrlich nicht messbar.
        check = scanner.check_rdp()
        assert check.passed is False
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN


class TestClassifyRdp:
    """Pure-Logik-Tests der geschichteten SH-003-Entscheidung."""

    def test_listener_with_remote_session_is_high_no_cap(self):
        result = _classify_rdp(
            fdeny="0", service_start=None, listening=True, established=True
        )
        assert result is not None
        passed, severity, detail = result
        assert passed is False
        assert severity == Severity.HIGH
        assert "absichern" in detail.lower()

    def test_listener_without_session_is_critical(self):
        passed, severity, _ = _classify_rdp(
            fdeny="0", service_start=None, listening=True, established=False
        )
        assert passed is False
        assert severity == Severity.CRITICAL

    def test_policy_deny_passes(self):
        passed, _, _ = _classify_rdp(
            fdeny="1", service_start=None, listening=False, established=False
        )
        assert passed is True

    def test_service_disabled_passes(self):
        passed, _, _ = _classify_rdp(
            fdeny=None, service_start="4", listening=None, established=None
        )
        assert passed is True

    def test_policy_allow_but_no_listener_passes_no_cap(self):
        # Patrick 2026-06-26: Policy erlaubt RDP, aber kein Listener -> kein
        # realer Fernzugriff -> bestanden, KEIN Cap.
        passed, _, _ = _classify_rdp(
            fdeny="0", service_start="2", listening=False, established=False
        )
        assert passed is True

    def test_policy_deny_wins_over_session(self):
        # fDeny=1 autoritativ: kein False-Positive durch Rest-/Fremdverbindung
        # auf 3389 (Review).
        passed, _, _ = _classify_rdp(
            fdeny="1", service_start="4", listening=True, established=True
        )
        assert passed is True

    def test_established_only_counts_under_listener(self):
        # established=True ohne Listener (transient/widerspruechlich) entlastet
        # NICHT, schadet aber auch nicht -> kein Listener = kein Fernzugriff.
        passed, _, _ = _classify_rdp(
            fdeny="0", service_start=None, listening=False, established=True
        )
        assert passed is True

    def test_all_unknown_is_not_measurable(self):
        assert (
            _classify_rdp(
                fdeny=None, service_start=None, listening=None, established=None
            )
            is None
        )

    def test_unknown_listener_policy_allow_is_not_measurable(self):
        # Probe fehlgeschlagen (listening None) UND Policy nicht „deny" -> ehrlich
        # nicht messbar; KEIN fail-closed-Cap auf nicht erreichbarem RDP.
        assert (
            _classify_rdp(
                fdeny="0", service_start=None, listening=None, established=None
            )
            is None
        )


class TestParseRdpPortState:
    """Parsing der _PS_RDP_PORT_STATE-Ausgabe."""

    def test_listen_and_established(self):
        from core.probes.hardening_probe import ProbeResult

        listening, established = _parse_rdp_port_state(
            ProbeResult(success=True, stdout="1,2")
        )
        assert listening is True
        assert established is True

    def test_zero_counts(self):
        from core.probes.hardening_probe import ProbeResult

        listening, established = _parse_rdp_port_state(
            ProbeResult(success=True, stdout="0,0")
        )
        assert listening is False
        assert established is False

    def test_probe_failure_is_none(self):
        from core.probes.hardening_probe import ProbeResult

        assert _parse_rdp_port_state(ProbeResult(success=False)) == (None, None)

    @pytest.mark.parametrize("bad", ["", "1", "1,2,3", "x,y", "abc"])
    def test_unparsable_is_none(self, bad):
        from core.probes.hardening_probe import ProbeResult

        assert _parse_rdp_port_state(
            ProbeResult(success=True, stdout=bad)
        ) == (None, None)


# ===========================================================================
# SH-004 — Automatische Updates
# ===========================================================================


_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=UTC)


def _ts(dt: datetime) -> str:
    """Formatiert ein datetime wie der Windows-Update-Agent (locale-frei UTC)."""
    return dt.strftime(_WU_TIMESTAMP_FORMAT)


class TestParseWuTimestamp:
    def test_valid_roundtrips_utc_aware(self):
        dt = _parse_wu_timestamp("2026-06-20 13:45:12")
        assert dt == datetime(2026, 6, 20, 13, 45, 12, tzinfo=UTC)

    def test_strips_whitespace(self):
        assert _parse_wu_timestamp("  2026-06-20 13:45:12  ") is not None

    @pytest.mark.parametrize("raw", [None, "", "   ", "kein-datum", "2026/06/20"])
    def test_unparsable_returns_none(self, raw):
        assert _parse_wu_timestamp(raw) is None


class TestClassifyAutoUpdate:
    """Pure-Logik-Tests der geschichteten SH-004-Entscheidung."""

    def _fresh(self) -> str:
        return _ts(_NOW - timedelta(days=2))

    def test_service_disabled_fails(self):
        passed, detail = _classify_auto_update(
            service_start="4",
            au_options="4",
            last_search=self._fresh(),
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is False
        assert "deaktiviert" in detail.lower()

    def test_service_disabled_takes_precedence_over_fresh_search(self):
        # Selbst bei frischer Suche gewinnt der deaktivierte Dienst (Root-Cause).
        _, detail = _classify_auto_update(
            service_start="4",
            au_options=None,
            last_search=self._fresh(),
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert "dienst" in detail.lower()

    @pytest.mark.parametrize("au", ["1", "2"])
    def test_au_options_no_auto_fails(self, au):
        passed, detail = _classify_auto_update(
            service_start="2",
            au_options=au,
            last_search=self._fresh(),
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is False
        assert "richtlinie" in detail.lower()

    @pytest.mark.parametrize("au", ["3", "4", "5", None])
    def test_au_options_auto_does_not_block_when_fresh(self, au):
        passed, _ = _classify_auto_update(
            service_start="2",
            au_options=au,
            last_search=self._fresh(),
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is True

    def test_fresh_search_passes_with_install_context(self):
        passed, detail = _classify_auto_update(
            service_start="3",
            au_options=None,
            last_search=_ts(_NOW - timedelta(days=2)),
            last_install=_ts(_NOW - timedelta(days=15)),
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is True
        assert "2026-06-24" in detail  # letzte Suche
        assert "2026-06-11" in detail  # letzte Installation als Kontext

    def test_stale_search_fails_with_age_and_date(self):
        passed, detail = _classify_auto_update(
            service_start="3",
            au_options=None,
            last_search=_ts(_NOW - timedelta(days=20)),
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is False
        assert "20 Tagen" in detail
        assert "2026-06-06" in detail

    def test_boundary_exactly_threshold_passes(self):
        # search_age == 14 ist NICHT > 14 -> bestanden.
        passed, _ = _classify_auto_update(
            service_start="3",
            au_options=None,
            last_search=_ts(_NOW - timedelta(days=_MAX_SEARCH_AGE_DAYS)),
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is True

    def test_boundary_one_day_over_threshold_fails(self):
        passed, _ = _classify_auto_update(
            service_start="3",
            au_options=None,
            last_search=_ts(_NOW - timedelta(days=_MAX_SEARCH_AGE_DAYS + 1)),
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is False

    def test_no_search_record_fails(self):
        passed, detail = _classify_auto_update(
            service_start="3",
            au_options=None,
            last_search=None,
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is False
        assert "keine verlaessliche erfolgreiche update-suche" in detail.lower()

    def test_install_only_without_search_fails(self):
        # last_install allein ersetzt NICHT die fehlende erfolgreiche Suche.
        passed, _ = _classify_auto_update(
            service_start="3",
            au_options=None,
            last_search=None,
            last_install=_ts(_NOW - timedelta(days=1)),
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is False

    @pytest.mark.parametrize("delta", [timedelta(hours=1), timedelta(days=5)])
    def test_future_timestamp_fails_fail_closed(self, delta):
        # Zukunfts-Timestamp (Uhr-Skew/Manipulation) ist KEIN Beweis -> Verstoss,
        # ohne den unplausiblen Wert ("heute") faelschlich gruen zu zeigen.
        passed, detail = _classify_auto_update(
            service_start="3",
            au_options=None,
            last_search=_ts(_NOW + delta),
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is False
        assert "verlaessliche" in detail.lower()

    def test_sentinel_1601_timestamp_fails_without_absurd_age(self):
        # Windows schreibt 1601-01-01 als „nie gelaufen" -> nicht „Seit 155000
        # Tagen", sondern fail-closed mit klarer Meldung.
        passed, detail = _classify_auto_update(
            service_start="3",
            au_options=None,
            last_search="1601-01-01 00:00:00",
            last_install=None,
            now=_NOW,
            max_search_age_days=_MAX_SEARCH_AGE_DAYS,
        )
        assert passed is False
        assert "verlaessliche" in detail.lower()
        assert "1601" not in detail  # absurder Wert wird NICHT angezeigt


class TestAgePhrase:
    @pytest.mark.parametrize(
        "days,expected",
        [(0, "heute"), (1, "vor 1 Tag"), (7, "vor 7 Tagen"), (14, "vor 14 Tagen")],
    )
    def test_phrases(self, days, expected):
        assert _age_phrase(days) == expected

    @pytest.mark.parametrize("days", [-1, -100])
    def test_non_positive_collapses_to_heute(self, days):
        assert _age_phrase(days) == "heute"


class TestSh004AutoUpdate:
    """Check-Methoden-Tests gegen die MockProbe (deterministisch via now=_NOW)."""

    def _set_service(self, probe, start: str) -> None:
        probe.set_registry_value(
            HIVE_HKLM, _WUAUSERV_START_KEY, _WUAUSERV_START_VALUE, start
        )

    def _set_last_search(self, probe, dt: datetime) -> None:
        probe.set_registry_value(
            HIVE_HKLM, _WU_RESULTS_DETECT_KEY, _WU_LAST_SUCCESS_VALUE, _ts(dt)
        )

    def test_no_signal_is_not_applicable(self, scanner):
        # Kein Registry-Wert gesetzt -> ehrlich nicht messbar, terminal n/a
        # (kein NEEDS_ADMIN -> kein Recheck-Karussell).
        check = scanner.check_auto_update(now=_NOW)
        assert check.check_id == SH_004_AUTO_UPDATE
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.NOT_APPLICABLE

    def test_service_disabled_fails_measurable(self, scanner, probe):
        self._set_service(probe, "4")
        check = scanner.check_auto_update(now=_NOW)
        assert check.passed is False
        assert check.measurable is True
        assert check.severity == Severity.HIGH

    def test_fresh_search_passes(self, scanner, probe):
        self._set_service(probe, "2")
        self._set_last_search(probe, _NOW - timedelta(days=2))
        check = scanner.check_auto_update(now=_NOW)
        assert check.passed is True
        assert check.measurable is True

    def test_stale_search_fails(self, scanner, probe):
        self._set_service(probe, "2")
        self._set_last_search(probe, _NOW - timedelta(days=40))
        check = scanner.check_auto_update(now=_NOW)
        assert check.passed is False
        assert check.measurable is True

    def test_au_options_overlay_fails_even_if_service_ok(self, scanner, probe):
        self._set_service(probe, "2")
        self._set_last_search(probe, _NOW - timedelta(days=1))
        probe.set_registry_value(
            HIVE_HKLM, _WU_AUTO_UPDATE_KEY, "AUOptions", "1"
        )
        check = scanner.check_auto_update(now=_NOW)
        assert check.passed is False
        assert "richtlinie" in check.detail.lower()


# ===========================================================================
# SH-005 — SMBv1
# ===========================================================================


class TestSh005Smbv1:
    _SCRIPT = "(Get-SmbServerConfiguration).EnableSMB1Protocol"

    def test_smbv1_disabled_passes(self, scanner, probe):
        probe.set_powershell_result(self._SCRIPT, stdout="False")
        check = scanner.check_smbv1()
        assert check.check_id == SH_005_SMBV1
        assert check.passed is True
        assert check.severity == Severity.CRITICAL

    def test_smbv1_enabled_fails(self, scanner, probe):
        probe.set_powershell_result(self._SCRIPT, stdout="True")
        check = scanner.check_smbv1()
        assert check.passed is False

    def test_powershell_failure(self, scanner):
        check = scanner.check_smbv1()
        assert check.passed is False
        assert check.measurable is False  # Probe-Fehler = nicht messbar


# ===========================================================================
# SH-006 — Gastkonto
# ===========================================================================


class TestSh006GuestAccount:
    def test_guest_disabled_passes_english(self, scanner, probe):
        probe.set_command_result(
            "net",
            ["user", "Guest"],
            stdout=(
                "User name                    Guest\n"
                "Full Name\n"
                "Comment                      Built-in account for guest access\n"
                "Account active             No\n"
            ),
        )
        check = scanner.check_guest_account()
        assert check.passed is True

    def test_guest_enabled_fails(self, scanner, probe):
        probe.set_command_result(
            "net",
            ["user", "Guest"],
            stdout=(
                "User name                    Guest\n"
                "Account active             Yes\n"
            ),
        )
        check = scanner.check_guest_account()
        assert check.passed is False
        assert "AKTIV" in check.detail

    def test_neither_command_works(self, scanner):
        check = scanner.check_guest_account()
        assert check.passed is False
        assert check.measurable is False  # Probe-Fehler = nicht messbar

    def test_unparseable_locale_is_not_measurable(self, scanner, probe):
        # Phase 0: net user LAEUFT, aber nicht-DE/EN-Locale -> Aktiv-Status nicht
        # parsebar. Frueher: faelschlich passed=False (Fehl-MEDIUM). Jetzt
        # measurable=False (kein erfundener Verstoss).
        probe.set_command_result(
            "net",
            ["user", "Guest"],
            stdout=(
                "Nom d'utilisateur            Invite\n"
                "Compte actif                 Oui\n"
            ),
        )
        check = scanner.check_guest_account()
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.PARSE_FAILED
        assert "nicht messbar" in check.detail.lower()

    # --- Phase 2: locale-freie Get-LocalUser-Primaerabfrage -------

    def test_powershell_primary_disabled_passes(self, scanner, probe):
        probe.set_powershell_result(_PS_GUEST_ACCOUNT, stdout="disabled")
        check = scanner.check_guest_account()
        assert check.passed is True

    def test_powershell_primary_enabled_fails(self, scanner, probe):
        probe.set_powershell_result(_PS_GUEST_ACCOUNT, stdout="enabled")
        check = scanner.check_guest_account()
        assert check.passed is False

    def test_powershell_primary_absent_passes(self, scanner, probe):
        # Kein Gastkonto vorhanden = sicherer Zustand -> passed.
        probe.set_powershell_result(_PS_GUEST_ACCOUNT, stdout="absent")
        check = scanner.check_guest_account()
        assert check.passed is True
        assert "kein gastkonto" in check.detail.lower()


# ===========================================================================
# SH-007 — Passwort-Policy
# ===========================================================================


class TestSh007PasswordPolicy:
    def test_min_length_8_passes(self, scanner, probe):
        probe.set_command_result(
            "net",
            ["accounts"],
            stdout="Minimum password length:                  8\n",
        )
        check = scanner.check_password_policy()
        assert check.passed is True

    def test_min_length_4_fails(self, scanner, probe):
        probe.set_command_result(
            "net",
            ["accounts"],
            stdout="Minimum password length:                  4\n",
        )
        check = scanner.check_password_policy()
        assert check.passed is False

    def test_not_parseable_output(self, scanner, probe):
        probe.set_command_result(
            "net", ["accounts"], stdout="Something completely unrelated\n",
        )
        check = scanner.check_password_policy()
        # Output nicht interpretierbar (Locale) -> nicht messbar.
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.PARSE_FAILED
        assert "nicht messbar" in check.detail.lower()

    def test_parse_password_min_length_helper(self):
        # Englisch
        assert (
            _parse_password_min_length(
                "Minimum password length:                  8\n"
            )
            == 8
        )
        # Deutsch
        assert (
            _parse_password_min_length(
                "Mindestlaenge des Kennworts:              10\n"
            )
            == 10
        )
        # Andere deutsche Variante
        assert (
            _parse_password_min_length(
                "Minimale Kennwortlaenge:                  12\n"
            )
            == 12
        )
        # Nicht parsebar
        assert _parse_password_min_length("foo bar") is None


# ===========================================================================
# SH-008 — Autorun
# ===========================================================================


class TestSh008Autorun:
    _PATH = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"

    def test_autorun_255_passes(self, scanner, probe):
        probe.set_registry_value(HIVE_HKLM, self._PATH, "NoDriveTypeAutoRun", "255")
        check = scanner.check_autorun()
        assert check.passed is True

    def test_autorun_0_fails(self, scanner, probe):
        probe.set_registry_value(HIVE_HKLM, self._PATH, "NoDriveTypeAutoRun", "0")
        check = scanner.check_autorun()
        assert check.passed is False

    def test_missing_value_default_active(self, scanner):
        # Wert fehlt → Default = Autorun aktiv → passed=False
        check = scanner.check_autorun()
        assert check.passed is False
        assert "fehlt" in check.detail

    def test_non_numeric_value(self, scanner, probe):
        probe.set_registry_value(
            HIVE_HKLM, self._PATH, "NoDriveTypeAutoRun", "garbage",
        )
        check = scanner.check_autorun()
        assert check.passed is False
        assert "nicht numerisch" in check.detail


# ===========================================================================
# SH-009 — Lokale Admins
# ===========================================================================


class TestSh009LocalAdmins:
    def test_two_admins_passes(self, scanner, probe):
        probe.set_command_result(
            "net",
            ["localgroup", "Administrators"],
            stdout=(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "\n"
                "-------------------------------------------------------------------------------\n"
                "Administrator\n"
                "Patrick\n"
                "The command completed successfully.\n"
            ),
        )
        check = scanner.check_local_admins()
        assert check.passed is True
        assert "2 Admin" in check.detail

    def test_three_admins_fails(self, scanner, probe):
        probe.set_command_result(
            "net",
            ["localgroup", "Administrators"],
            stdout=(
                "Members\n"
                "\n"
                "-------------------------------------------------------------------------------\n"
                "Administrator\n"
                "Patrick\n"
                "ExtraAdmin\n"
                "The command completed successfully.\n"
            ),
        )
        check = scanner.check_local_admins()
        assert check.passed is False
        assert "3 Admin" in check.detail

    def test_neither_locale_works(self, scanner):
        check = scanner.check_local_admins()
        assert check.passed is False
        assert check.measurable is False  # Probe-Fehler = nicht messbar
        assert check.unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN

    def test_parse_localgroup_member_count_helper(self):
        # Englisch
        stdout_en = (
            "Members\n"
            "\n"
            "-------------------------------------------------------------------------------\n"
            "Administrator\n"
            "Patrick\n"
            "The command completed successfully.\n"
        )
        assert _parse_localgroup_member_count(stdout_en) == 2

        # Deutsch
        stdout_de = (
            "Mitglieder\n"
            "\n"
            "-------------------------------------------------------------------------------\n"
            "Administrator\n"
            "Der Befehl wurde erfolgreich ausgefuehrt.\n"
        )
        assert _parse_localgroup_member_count(stdout_de) == 1

    # --- Phase 2: locale-freie Get-LocalGroupMember-Primaerabfrage

    def test_powershell_primary_count_within_limit_passes(self, scanner, probe):
        probe.set_powershell_result(_PS_LOCAL_ADMINS_COUNT, stdout="2")
        check = scanner.check_local_admins()
        assert check.passed is True
        assert "2 Admin" in check.detail
        assert "Get-LocalGroupMember" in check.detail

    def test_powershell_primary_count_over_limit_fails(self, scanner, probe):
        probe.set_powershell_result(_PS_LOCAL_ADMINS_COUNT, stdout="3")
        check = scanner.check_local_admins()
        assert check.passed is False


# ===========================================================================
# SH-010 — BitLocker
# ===========================================================================


class TestSh010Bitlocker:
    def test_bitlocker_active_passes_english(self, scanner, probe):
        probe.set_command_result(
            "manage-bde",
            ["-status", "C:"],
            stdout=(
                "Volume C:\n"
                "Protection Status:    Protection On\n"
                "Lock Status:          Unlocked\n"
            ),
        )
        check = scanner.check_bitlocker()
        assert check.passed is True

    def test_bitlocker_inactive_fails(self, scanner, probe):
        probe.set_command_result(
            "manage-bde",
            ["-status", "C:"],
            stdout=(
                "Volume C:\n"
                "Protection Status:    Protection Off\n"
            ),
        )
        check = scanner.check_bitlocker()
        assert check.passed is False

    def test_bitlocker_active_german(self, scanner, probe):
        probe.set_command_result(
            "manage-bde",
            ["-status", "C:"],
            stdout=(
                "Volume C:\n"
                "Schutzstatus:         Schutz aktiviert\n"
            ),
        )
        check = scanner.check_bitlocker()
        assert check.passed is True

    def test_manage_bde_failure(self, scanner):
        check = scanner.check_bitlocker()
        assert check.passed is False
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN

    # --- Phase 2: locale-freie Get-BitLockerVolume-Primaerabfrage -

    def test_powershell_primary_on_passes(self, scanner, probe):
        probe.set_powershell_result(_PS_BITLOCKER_C, stdout="On")
        check = scanner.check_bitlocker()
        assert check.passed is True
        assert "Get-BitLockerVolume" in check.detail

    def test_powershell_primary_off_fails(self, scanner, probe):
        probe.set_powershell_result(_PS_BITLOCKER_C, stdout="Off")
        check = scanner.check_bitlocker()
        assert check.passed is False
        assert check.measurable is True

    # --- SH-010 Edition-Gate: BitLocker existiert nicht auf Home/Core ---

    @pytest.mark.parametrize(
        "edition", ["Core", "CoreN", "CoreSingleLanguage", "CoreCountrySpecific"]
    )
    def test_home_edition_not_applicable(self, scanner, probe, edition):
        # Home/Core: BitLocker strukturell nicht da -> NOT_APPLICABLE, NICHT
        # needs_admin (sonst Endlos-"Mit Admin messen"; D6-Live-Befund 0x80041003).
        probe.set_powershell_result(_PS_EDITION_ID, stdout=edition)
        check = scanner.check_bitlocker()
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.NOT_APPLICABLE
        assert "Home" in check.detail

    def test_pro_edition_proceeds_to_probe(self, scanner, probe):
        probe.set_powershell_result(_PS_EDITION_ID, stdout="Professional")
        probe.set_powershell_result(_PS_BITLOCKER_C, stdout="On")
        check = scanner.check_bitlocker()
        assert check.passed is True
        assert check.measurable is True

    def test_unknown_edition_proceeds_to_probe(self, scanner, probe):
        # Edition nicht ermittelbar (Probe-Default) -> NICHT vorschnell n/a,
        # sondern normal weiterpruefen (Rueckwaerts-Kompatibilitaet).
        probe.set_powershell_result(_PS_BITLOCKER_C, stdout="On")
        check = scanner.check_bitlocker()
        assert check.passed is True

    def test_manage_bde_unparseable_locale_not_measurable(self, scanner, probe):
        # Review-P2: manage-bde lief, aber Nicht-DE/EN-Locale (FR) -> weder
        # "protection on" noch "off" -> NICHT als Verstoss (kein Fehl-MEDIUM),
        # sondern measurable=False/PARSE_FAILED (gleiche 3-Zustands-Logik).
        probe.set_command_result(
            "manage-bde",
            ["-status", "C:"],
            stdout=(
                "Volume C:\n"
                "Etat de la protection :    Protection activee\n"
            ),
        )
        check = scanner.check_bitlocker()
        assert check.measurable is False
        assert check.unmeasured_reason == UnmeasuredReason.PARSE_FAILED


# ===========================================================================
# scan_all — alle 10 zusammen
# ===========================================================================


class TestScanAll:
    def test_all_10_checks_returned(self, scanner):
        results = scanner.scan_all()
        assert len(results) == 10
        ids = [r.check_id for r in results]
        assert ids == [
            SH_001_FIREWALL,
            SH_002_UAC,
            SH_003_RDP,
            SH_004_AUTO_UPDATE,
            SH_005_SMBV1,
            SH_006_GUEST_ACCOUNT,
            SH_007_PASSWORD_POLICY,
            SH_008_AUTORUN,
            SH_009_LOCAL_ADMINS,
            SH_010_BITLOCKER,
        ]

    def test_default_mock_all_failed(self, scanner):
        # Ohne Mock-Konfiguration: alle Checks failed
        results = scanner.scan_all()
        assert all(not r.passed for r in results)

    def test_perfect_compliant_setup(self, scanner, probe):
        """Test: alle 10 Checks bestanden — System ist vollstaendig konform."""
        # SH-001 Firewall
        probe.set_command_result(
            "netsh",
            ["advfirewall", "show", "allprofiles", "state"],
            stdout=(
                "State                                 ON\n"
                "State                                 ON\n"
                "State                                 ON\n"
            ),
        )
        # SH-002 UAC
        probe.set_registry_value(
            HIVE_HKLM,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA",
            "1",
        )
        # SH-003 RDP
        probe.set_registry_value(
            HIVE_HKLM,
            "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            "fDenyTSConnections",
            "1",
        )
        # SH-004 AutoUpdate: Dienst aktiv + frische letzte Suche.
        probe.set_registry_value(
            HIVE_HKLM, _WUAUSERV_START_KEY, _WUAUSERV_START_VALUE, "2"
        )
        probe.set_registry_value(
            HIVE_HKLM,
            _WU_RESULTS_DETECT_KEY,
            _WU_LAST_SUCCESS_VALUE,
            _ts(datetime.now(UTC) - timedelta(days=1)),
        )
        # SH-005 SMBv1
        probe.set_powershell_result(
            "(Get-SmbServerConfiguration).EnableSMB1Protocol", stdout="False",
        )
        # SH-006 Guest
        probe.set_command_result(
            "net", ["user", "Guest"], stdout="Account active             No\n",
        )
        # SH-007 PWPolicy
        probe.set_command_result(
            "net",
            ["accounts"],
            stdout="Minimum password length:                  12\n",
        )
        # SH-008 Autorun
        probe.set_registry_value(
            HIVE_HKLM,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            "NoDriveTypeAutoRun",
            "255",
        )
        # SH-009 Local Admins (2 = Schwelle)
        probe.set_command_result(
            "net",
            ["localgroup", "Administrators"],
            stdout=(
                "Members\n\n"
                "-------------------------------------------------------------------------------\n"
                "Administrator\n"
                "Patrick\n"
                "The command completed successfully.\n"
            ),
        )
        # SH-010 BitLocker
        probe.set_command_result(
            "manage-bde",
            ["-status", "C:"],
            stdout="Protection Status:    Protection On\n",
        )

        results = scanner.scan_all()
        assert all(r.passed for r in results), [
            (r.check_id, r.detail) for r in results if not r.passed
        ]
