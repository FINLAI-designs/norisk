"""
test_phishing_radar_viewmodel — Tests fuer das reine ViewModel
``PhishingRadarViewModel`` (kein Qt). Verifiziert die Default-Filter
und das Verhalten bei fehlendem Service.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tools.cyber_dashboard.application.dashboard_service import (
    DashboardService,
)
from tools.cyber_dashboard.application.rss_service import RssService
from tools.cyber_dashboard.data.cache_repository import CacheRepository
from tools.cyber_dashboard.domain.models import (
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
)
from tools.mainpage.gui.phishing_radar_data import PhishingRadarViewModel


def _service() -> DashboardService:
    return DashboardService(rss=RssService(), cache=CacheRepository())


def _meldung(guid: str, quelle: QuelleTyp = QuelleTyp.WATCHLIST_AT) -> CyberMeldung:
    return CyberMeldung(
        titel=f"Phishing-Vorfall {guid}",
        beschreibung="Test",
        url=f"https://example.com/{guid}",
        quelle=quelle,
        schweregrad=Schweregrad.HOCH,
        veroeffentlicht=datetime.now(UTC) - timedelta(hours=1),
        guid=guid,
    )


class TestOhneService:
    def test_banner_daten_leer_und_unbereit(self) -> None:
        vm = PhishingRadarViewModel(None)
        d = vm.banner_daten()
        assert not d.bereit
        assert d.items == []
        assert d.neue_24h == 0
        assert d.ungelesen == 0

    def test_inbox_items_leer(self) -> None:
        vm = PhishingRadarViewModel(None)
        assert vm.inbox_items() == []

    def test_markier_methoden_no_op(self) -> None:
        vm = PhishingRadarViewModel(None)
        vm.markiere_gelesen(["x"])  # darf nicht knallen
        vm.markiere_ungelesen(["x"])
        vm.schiebe_auf("x", datetime.now(UTC))


class TestMitService:
    def test_banner_daten_zaehlt_und_liefert_items(self) -> None:
        svc = _service()
        for i in range(8):
            svc._cache.speichere_meldungen([_meldung(f"b-{i}")])
        vm = PhishingRadarViewModel(svc, modus="easy")
        d = vm.banner_daten()
        assert d.bereit
        assert d.neue_24h == 8
        assert len(d.items) <= 6  # Banner-Limit ist 6 AP3)

    def test_modus_expert_oeffnet_awareness(self) -> None:
        svc = _service()
        # _meldung defaultet auf Schweregrad.HOCH — fuer den Test ist
        # nur die Quelle (= Kategorie) entscheidend.
        svc._cache.speichere_meldungen(
            [_meldung("k-1", QuelleTyp.KREBS)]
        )
        vm = PhishingRadarViewModel(svc, modus="easy")
        d_easy = vm.banner_daten()
        # Easy zeigt nur Konsumenten — Krebs ist AWARENESS, deshalb 0.
        assert d_easy.neue_24h == 0

        vm.set_modus("expert")
        d_expert = vm.banner_daten()
        # Expert oeffnet Konsumenten + Awareness — Krebs wird gezaehlt.
        assert d_expert.neue_24h == 1
