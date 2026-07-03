"""
test_cve_tab_filter_diagnose — Diagnose-Tests fuer.

Patrick-Smoke 2026-05-12: CVE-Tab zeigt "Keine CVEs im Cache" obwohl
KEV-Counter 77 anzeigt. Hypothese: Filter-Default ist hardcoded auf
CRITICAL → keine CRITICAL-Daten im Cache → leerer Tab.

Diese Tests reproduzieren die Daten-Konstellation und pruefen ob
``lade_cves(schweregrad=None)`` tatsaechlich alle 77 Eintraege
zurueckgibt — oder ob ein anderer Bug greift.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tools.cyber_dashboard.data.cache_repository import CacheRepository
from tools.cyber_dashboard.domain.models import CveEintrag


def _make_kev(cve_id: str, days_ago: int) -> CveEintrag:
    """Baut ein KEV-CveEintrag analog ``cisa_kev_client._zu_cve_eintrag``.

    Wichtig: ``veroeffentlicht`` ist ``dateAdded`` (Tag-Granular ohne
    Uhrzeit-Anteil im Original-Feed) — wir mimen das nach, weil das
    der reale Production-State ist.
    """
    # ACHTUNG: CISA-KEV-Feed liefert "YYYY-MM-DD". Das wird im Client
    # via ``strptime("%Y-%m-%d").replace(tzinfo=UTC)`` zu Mitternacht.
    added = (
        datetime.now(UTC) - timedelta(days=days_ago)
    ).replace(hour=0, minute=0, second=0, microsecond=0)
    return CveEintrag(
        cve_id=cve_id,
        beschreibung="test",
        schweregrad="HIGH",
        cvss_score=9.0,
        veroeffentlicht=added,
        geaendert=added,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        cisa_kev=True,
        cisa_frist="",
        betroffene_produkte=["Vendor X"],
    )


def _make_kev_recent(cve_id: str, hours_ago: int) -> CveEintrag:
    """Baut ein KEV-CveEintrag mit Stunden-genauem Veroeffentlichungs-
    Datum innerhalb der letzten 24h. Fuer-Counter-Tests, die
    explizit den ``veroeffentlicht >= jetzt - 24h``-Filter triggern."""
    added = datetime.now(UTC) - timedelta(hours=hours_ago)
    return CveEintrag(
        cve_id=cve_id,
        beschreibung="test",
        schweregrad="HIGH",
        cvss_score=9.0,
        veroeffentlicht=added,
        geaendert=added,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        cisa_kev=True,
        cisa_frist="",
        betroffene_produkte=["Vendor X"],
    )


class TestCveTabFilterDiagnose:
    """Reproduktion der Patrick-Symptome — sucht den echten Bug-Pfad.

    Counter filtert seit diesem Fix auf
    ``veroeffentlicht``, nicht ``geladen_am``. Die Test-Asserts wurden
    entsprechend angepasst — nur CVEs mit Veroeffentlichungs-Datum
    innerhalb der letzten 24h werden gezaehlt.
    """

    def test_kev_data_persists_and_loads_with_no_filter(self) -> None:
        """Smoke: 10 KEV-CVEs gleichmaessig in den letzten 24h
        → counter zeigt 10 → load liefert 10."""
        repo = CacheRepository()
        # Alle innerhalb der letzten 24h veroeffentlicht (Stunden statt Tage)
        cves = [
            _make_kev_recent(f"CVE-2026-{i:04d}", hours_ago=i) for i in range(10)
        ]
        repo.speichere_cves(cves)

        counts = repo.zaehle_cves_nach_schweregrad()
        assert counts["HIGH"] == 10
        assert counts["kev"] == 10

        # lade_cves ohne Filter — sollte alle 10 zurueckgeben
        loaded = repo.lade_cves(schweregrad=None, nur_kev=False, limit=50)
        assert len(loaded) == 10, (
            f"BUG-Reproduktion: counter zeigt 10 KEVs, lade_cves nur "
            f"{len(loaded)}. Pruefe das Row-Parsing in lade_cves."
        )

    def test_kev_data_with_realistic_dateadded_format(self) -> None:
        """Realer Production-Pfad: 77 KEVs aus den letzten 90 Tagen.

 Verhalten: Counter zeigt nur die innerhalb der letzten
        24h veroeffentlichten. Bei ``days_ago = i % 90`` sind das
        genau die Eintraege mit ``i % 90 == 0`` — also 1 Eintrag fuer
        ``i in (0,)`` (i=90 wuerde 91 sein, ist aber nicht in [0,77)).
        """
        repo = CacheRepository()
        cves = [
            _make_kev(f"CVE-2026-{1000 + i:04d}", days_ago=(i % 90))
            for i in range(77)
        ]
        repo.speichere_cves(cves)

        counts = repo.zaehle_cves_nach_schweregrad()
        # Counter sieht nur die mit veroeffentlicht in last-24h
        assert counts["HIGH"] == 1
        assert counts["kev"] == 1
        assert counts["CRITICAL"] == 0

        # lade_cves ohne 24h-Filter — alle 77, limitiert auf 50.
        loaded = repo.lade_cves(schweregrad=None, nur_kev=False, limit=50)
        assert len(loaded) == 50

    def test_lade_cves_with_critical_filter_returns_empty_when_no_critical(
        self,
    ) -> None:
        """Wenn der User aktiv 'CRITICAL' im Combo waehlt aber nur HIGH-
        Daten vorhanden sind, liefert lade_cves leer — das ist KORREKT
        (nicht der Bug)."""
        repo = CacheRepository()
        cves = [_make_kev(f"CVE-2026-{i:04d}", days_ago=i) for i in range(5)]
        repo.speichere_cves(cves)

        loaded = repo.lade_cves(schweregrad="CRITICAL", nur_kev=False, limit=50)
        assert loaded == []  # erwartet leer — nur HIGH im Cache

    def test_lade_cves_handles_kev_dateadded_midnight_iso(self) -> None:
        """KEV-Daten haben '00:00:00+00:00'-Timestamp (Tag-Granular).
        Pruefe dass datetime.fromisoformat das wieder parsen kann."""
        repo = CacheRepository()
        # Explizite Midnight-UTC-Zeit
        added = datetime(2026, 1, 15, 0, 0, 0, tzinfo=UTC)
        cve = CveEintrag(
            cve_id="CVE-2026-1234",
            beschreibung="test",
            schweregrad="HIGH",
            cvss_score=9.0,
            veroeffentlicht=added,
            geaendert=added,
            url="",
            cisa_kev=True,
            cisa_frist="",
            betroffene_produkte=[],
        )
        repo.speichere_cves([cve])
        loaded = repo.lade_cves()
        assert len(loaded) == 1
        assert loaded[0].cve_id == "CVE-2026-1234"


class TestCveTabFilterWiderspruch:
    """Pruefe ob die Counter-vs-Load-Inkonsistenz reproduzierbar ist.

    Counter filtert auf ``veroeffentlicht >=
    jetzt - 24h``. lade_cves filtert nicht nach Datum. Tests
    dokumentieren beide Sichten konsistent.
    """

    def test_recent_veroeffentlicht_counter_und_load_konsistent(self) -> None:
        """15 CVEs alle in den letzten 24h veroeffentlicht. Counter und
        Load sehen beide 15."""
        repo = CacheRepository()
        cves = [
            _make_kev_recent(f"CVE-2026-{i:04d}", hours_ago=i) for i in range(15)
        ]
        repo.speichere_cves(cves)

        counts = repo.zaehle_cves_nach_schweregrad()
        loaded = repo.lade_cves(schweregrad=None)

        assert counts["HIGH"] == 15
        assert len(loaded) == 15

    def test_alte_veroeffentlichung_zaehlt_nicht_im_24h_counter(self) -> None:
        """ Regression: 5 KEVs alle aelter als 24h
        (``days_ago=2``). Counter ist 0, lade_cves liefert trotzdem 5."""
        repo = CacheRepository()
        cves = [_make_kev(f"CVE-2026-{i:04d}", days_ago=2) for i in range(5)]
        repo.speichere_cves(cves)

        counts = repo.zaehle_cves_nach_schweregrad()
        loaded = repo.lade_cves(schweregrad=None)

        # Frueher (Bug): Counter haette 5 gezeigt weil geladen_am=jetzt.
        # Nach Fix: 0 weil veroeffentlicht 2 Tage alt.
        assert counts["HIGH"] == 0
        assert counts["kev"] == 0
        # lade_cves filtert nicht nach Datum
        assert len(loaded) == 5
