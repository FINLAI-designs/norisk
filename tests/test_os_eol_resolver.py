"""
test_os_eol_resolver.

Tests fuer den OS-EOL-Resolver. Wir injizieren ein festes ``today``-Datum,
damit die Tests deterministisch sind (Catalog-Daten relativ dazu).
"""

from __future__ import annotations

from datetime import date

import pytest

from core.os_eol_resolver import (
    OsEolEntry,
    catalog,
    resolve_os,
)

# Fest gewaehltes Referenz-Datum — alle EOL-Aussagen relativ dazu.
TODAY = date(2026, 5, 16)


class TestCatalog:
    def test_enthaelt_mindestens_alle_relevanten_windows_versionen(self) -> None:
        names = {e.name for e in catalog()}
        # Wichtige Stop-Points fuer Kanzleien.
        assert "Windows 7" in names
        assert "Windows 8.1" in names
        assert "Windows 10" in names
        assert "Windows 11" in names
        assert "Windows Server 2012 R2" in names

    def test_alle_eintraege_haben_eol_date(self) -> None:
        for entry in catalog():
            assert isinstance(entry.eol_date, date)


class TestResolveOs:
    def test_windows_10_ist_eol_seit_2025(self) -> None:
        status = resolve_os("Microsoft Windows 10 Pro", today=TODAY)
        assert status.is_eol is True
        assert status.matched_entry is not None
        assert status.matched_entry.name == "Windows 10"
        assert status.days_until_eol is not None
        assert status.days_until_eol < 0

    def test_windows_11_ist_noch_supported(self) -> None:
        status = resolve_os("Microsoft Windows 11 Enterprise", today=TODAY)
        assert status.is_eol is False
        assert status.matched_entry is not None
        assert status.matched_entry.name == "Windows 11"
        assert status.days_until_eol is not None
        assert status.days_until_eol > 0

    def test_windows_8_1_matcht_nicht_windows_8(self) -> None:
        """Substring-Match muss den laengsten Treffer waehlen — sonst
        wuerde "Windows 8.1" auf "Windows 8" matchen."""
        status = resolve_os("Microsoft Windows 8.1 Pro x64", today=TODAY)
        assert status.matched_entry is not None
        assert status.matched_entry.name == "Windows 8.1"

    def test_windows_server_2012_r2_matcht_nicht_2012(self) -> None:
        status = resolve_os(
            "Microsoft Windows Server 2012 R2 Standard", today=TODAY
        )
        assert status.matched_entry is not None
        assert status.matched_entry.name == "Windows Server 2012 R2"

    def test_unbekanntes_os_failsafe(self) -> None:
        status = resolve_os("Ubuntu 22.04 LTS", today=TODAY)
        assert status.matched_entry is None
        assert status.is_eol is False
        assert status.days_until_eol is None

    def test_leeres_os_wird_failsafe(self) -> None:
        status = resolve_os("   ", today=TODAY)
        assert status.matched_entry is None
        assert status.is_eol is False

    def test_expiring_soon_innerhalb_180_tage(self) -> None:
        # Synthetisches OS, dessen EOL in 60 Tagen liegt.
        entry = OsEolEntry(
            name="TestOS",
            family="windows-client",
            eol_date=date(2026, 7, 15),  # in 60 Tagen ab TODAY
        )
        # Statt im realen Catalog: wir testen via direkte Berechnung
        # ueber resolve_os fuer Windows 10 (das ist schon EOL → days < 0).
        # Stattdessen direkt: in OsEolStatus.is_expiring_soon-Logik.
        # Aus dem Catalog: Windows Server 2016 EOL 2027-01-12 — wir testen
        # den Pfad mit einem fix-Today-Wert, der das in den 180-Tage-Fenster
        # bringt.
        soon_today = date(2026, 8, 1)
        status = resolve_os("Microsoft Windows Server 2016", today=soon_today)
        # EOL date is 2027-01-12, days = 164 → is_expiring_soon True.
        assert status.is_expiring_soon is True
        assert status.is_eol is False
        _ = entry  # silence ruff — entry war nur zur Dokumentation

    def test_expiring_soon_false_wenn_lang_in_zukunft(self) -> None:
        status = resolve_os("Microsoft Windows 11", today=TODAY)
        assert status.is_expiring_soon is False

    def test_case_insensitive(self) -> None:
        a = resolve_os("MICROSOFT WINDOWS 10 PRO", today=TODAY)
        b = resolve_os("microsoft windows 10 pro", today=TODAY)
        assert a.matched_entry == b.matched_entry


class TestHeadline:
    def test_eol_headline_enthaelt_eol_datum(self) -> None:
        status = resolve_os("Microsoft Windows 10", today=TODAY)
        assert "End-of-Life" in status.headline
        assert "2025-10-14" in status.headline

    def test_expiring_soon_headline_zeigt_remaining_days(self) -> None:
        status = resolve_os(
            "Microsoft Windows Server 2016", today=date(2026, 11, 1)
        )
        if status.is_expiring_soon:
            assert "Tage" in status.headline

    def test_unbekannt_headline(self) -> None:
        status = resolve_os("Some unknown OS", today=TODAY)
        assert "unbekannt" in status.headline.lower()


# ---------------------------------------------------------------------------
# OsEolStatus property-Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "os_name,expected_is_eol",
    [
        ("Microsoft Windows 7 Pro", True),
        ("Microsoft Windows 8.1 Pro", True),
        ("Microsoft Windows 10 Home", True),
        ("Microsoft Windows 11 Pro", False),
        ("Microsoft Windows Server 2012 R2", True),
        ("Microsoft Windows Server 2019 Standard", False),
    ],
)
def test_kanzlei_relevante_os_eol_table(
    os_name: str, expected_is_eol: bool
) -> None:
    status = resolve_os(os_name, today=TODAY)
    assert status.is_eol is expected_is_eol, (
        f"{os_name}: erwartet is_eol={expected_is_eol}, war {status.is_eol}"
    )


# ---------------------------------------------------------------------------
# OsEolStatus equality / dataclass-frozen
# ---------------------------------------------------------------------------


def test_os_eol_status_ist_frozen() -> None:
    status = resolve_os("Microsoft Windows 10", today=TODAY)
    # Frozen dataclass — attribute setting wirft.
    with pytest.raises(Exception):  # noqa: B017, PT011
        status.is_eol = False  # type: ignore[misc]
