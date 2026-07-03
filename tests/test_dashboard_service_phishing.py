"""
test_dashboard_service_phishing — Tests fuer die neuen Phishing-API-
Methoden auf ``DashboardService`` (Phishing-Radar-Refactor
2026-05-28): ``lade_phishing_alerts``, ``markiere_gelesen``,
``markiere_ungelesen``, ``schiebe_auf``, ``zaehle_ungelesene``,
``zaehle_seit``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.cyber_dashboard.application.dashboard_service import (
    DashboardService,
)
from tools.cyber_dashboard.application.rss_service import RssService
from tools.cyber_dashboard.data.cache_repository import CacheRepository
from tools.cyber_dashboard.domain.models import (
    CyberMeldung,
    Kategorie,
    QuelleTyp,
    Schweregrad,
)


@pytest.fixture
def service() -> DashboardService:
    return DashboardService(rss=RssService(), cache=CacheRepository())


def _meldung(
    guid: str,
    quelle: QuelleTyp = QuelleTyp.WATCHLIST_AT,
    severity: Schweregrad = Schweregrad.HOCH,
    vor_stunden: int = 1,
) -> CyberMeldung:
    return CyberMeldung(
        titel=f"Test {guid}",
        beschreibung="Test",
        url=f"https://example.com/{guid}",
        quelle=quelle,
        schweregrad=severity,
        veroeffentlicht=datetime.now(UTC) - timedelta(hours=vor_stunden),
        guid=guid,
    )


class TestLadePhishingAlerts:
    def test_filtert_nach_kategorie_konsumenten(
        self, service: DashboardService
    ) -> None:
        m1 = _meldung("c1", QuelleTyp.WATCHLIST_AT)
        m2 = _meldung("c2", QuelleTyp.MIMIKAMA)
        m3 = _meldung("c3", QuelleTyp.CERT_AT, severity=Schweregrad.KRITISCH)
        service._cache.speichere_meldungen([m1, m2, m3])
        alerts = service.lade_phishing_alerts(
            kategorien=[Kategorie.PHISHING_CONSUMER]
        )
        guids = {a.guid for a in alerts}
        assert "c1" in guids and "c2" in guids
        assert "c3" not in guids  # CERT_AT ist TECH_CVE

    def test_severity_filter(self, service: DashboardService) -> None:
        m_hoch = _meldung("sh", severity=Schweregrad.HOCH)
        m_mittel = _meldung("sm", severity=Schweregrad.MITTEL)
        m_niedrig = _meldung("sn", severity=Schweregrad.NIEDRIG)
        service._cache.speichere_meldungen([m_hoch, m_mittel, m_niedrig])
        alerts = service.lade_phishing_alerts(
            kategorien=[Kategorie.PHISHING_CONSUMER],
            min_schweregrad=Schweregrad.HOCH,
        )
        # MITTEL/NIEDRIG werden ausgefiltert.
        guids = {a.guid for a in alerts}
        assert "sh" in guids
        assert "sm" not in guids
        assert "sn" not in guids

    def test_zeit_filter(self, service: DashboardService) -> None:
        recent = _meldung("recent", vor_stunden=2)
        alt = _meldung("alt", vor_stunden=72)
        service._cache.speichere_meldungen([recent, alt])
        alerts_24h = service.lade_phishing_alerts(
            kategorien=[Kategorie.PHISHING_CONSUMER],
            seit_stunden=24,
        )
        guids = {a.guid for a in alerts_24h}
        assert "recent" in guids
        assert "alt" not in guids

    def test_nur_ungelesen(self, service: DashboardService) -> None:
        m1 = _meldung("u1")
        m2 = _meldung("u2")
        service._cache.speichere_meldungen([m1, m2])
        service._cache.markiere_gelesen(["u1"])
        alerts = service.lade_phishing_alerts(
            kategorien=[Kategorie.PHISHING_CONSUMER],
            nur_ungelesen=True,
        )
        guids = {a.guid for a in alerts}
        assert "u2" in guids
        assert "u1" not in guids

    def test_snooze_blendet_aus(self, service: DashboardService) -> None:
        m = _meldung("snoozed")
        service._cache.speichere_meldungen([m])
        bis = datetime.now(UTC) + timedelta(hours=12)
        service._cache.schiebe_auf("snoozed", bis, QuelleTyp.WATCHLIST_AT)
        alerts = service.lade_phishing_alerts(
            kategorien=[Kategorie.PHISHING_CONSUMER]
        )
        assert all(a.guid != "snoozed" for a in alerts)

    def test_sortierung_severity_desc(self, service: DashboardService) -> None:
        m_hoch = _meldung("ah", severity=Schweregrad.HOCH)
        m_krit = _meldung("ak", severity=Schweregrad.KRITISCH)
        service._cache.speichere_meldungen([m_hoch, m_krit])
        alerts = service.lade_phishing_alerts(
            kategorien=[Kategorie.PHISHING_CONSUMER],
            min_schweregrad=Schweregrad.MITTEL,
        )
        assert alerts[0].schweregrad == Schweregrad.KRITISCH

    def test_limit(self, service: DashboardService) -> None:
        for i in range(5):
            service._cache.speichere_meldungen([_meldung(f"lim-{i}")])
        alerts = service.lade_phishing_alerts(
            kategorien=[Kategorie.PHISHING_CONSUMER],
            limit=2,
        )
        assert len(alerts) <= 2


class TestZaehlfunktionen:
    def test_zaehle_seit(self, service: DashboardService) -> None:
        recent = _meldung("z-r", vor_stunden=1)
        alt = _meldung("z-a", vor_stunden=200)
        service._cache.speichere_meldungen([recent, alt])
        n = service.zaehle_seit([Kategorie.PHISHING_CONSUMER], stunden=24)
        assert n == 1

    def test_zaehle_ungelesene(self, service: DashboardService) -> None:
        m1 = _meldung("uz1")
        m2 = _meldung("uz2")
        service._cache.speichere_meldungen([m1, m2])
        service._cache.markiere_gelesen(["uz1"])
        n = service.zaehle_ungelesene([Kategorie.PHISHING_CONSUMER])
        assert n == 1


class TestMarkierFunktionen:
    def test_markiere_gelesen_und_ungelesen(
        self, service: DashboardService
    ) -> None:
        m = _meldung("mg")
        service._cache.speichere_meldungen([m])
        service.markiere_gelesen(["mg"])
        assert service.zaehle_ungelesene([Kategorie.PHISHING_CONSUMER]) == 0
        service.markiere_ungelesen(["mg"])
        assert service.zaehle_ungelesene([Kategorie.PHISHING_CONSUMER]) == 1

    def test_schiebe_auf_dekrementiert_zaehler(
        self, service: DashboardService
    ) -> None:
        m = _meldung("sa")
        service._cache.speichere_meldungen([m])
        assert service.zaehle_ungelesene([Kategorie.PHISHING_CONSUMER]) == 1
        bis = datetime.now(UTC) + timedelta(hours=4)
        service.schiebe_auf("sa", bis)
        assert service.zaehle_ungelesene([Kategorie.PHISHING_CONSUMER]) == 0

    def test_schiebe_auf_mit_quelle_ueberspringt_cache_scan(
        self, service: DashboardService
    ) -> None:
        """Wird die Quelle mitgegeben, faellt der 500-Zeilen-Scan weg."""
        from unittest.mock import patch

        bis = datetime.now(UTC) + timedelta(hours=4)
        with patch.object(service._cache, "lade_meldungen") as mock_load:
            service.schiebe_auf("sa-q", bis, QuelleTyp.MIMIKAMA)
            mock_load.assert_not_called()
        # Snooze wurde trotzdem persistiert.
        _gelesen, snooze_bis = service._cache.lade_state_fuer(["sa-q"])["sa-q"]
        assert snooze_bis is not None

    def test_schiebe_auf_ohne_quelle_scannt_cache_als_fallback(
        self, service: DashboardService
    ) -> None:
        from unittest.mock import patch

        bis = datetime.now(UTC) + timedelta(hours=4)
        with patch.object(
            service._cache, "lade_meldungen", return_value=[]
        ) as mock_load:
            service.schiebe_auf("sa-nf", bis)
            mock_load.assert_called_once()


class TestReadStateFuer:
    def test_liefert_nur_gelesene_guids(
        self, service: DashboardService
    ) -> None:
        service._cache.speichere_meldungen(
            [_meldung("rs1"), _meldung("rs2"), _meldung("rs3")]
        )
        service.markiere_gelesen(["rs1", "rs3"])
        gelesene = service.read_state_fuer(["rs1", "rs2", "rs3"])
        assert gelesene == {"rs1", "rs3"}

    def test_leere_eingabe(self, service: DashboardService) -> None:
        assert service.read_state_fuer([]) == set()
