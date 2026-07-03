"""
test_awareness_tracker_phishing_sim.

Tests fuer das Phishing-Sim-Modell, Repository-CRUD und Service-KPIs.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
    PhishingSimKpi,
)
from tools.awareness_tracker.data.awareness_repository import (
    AwarenessRepository,
)
from tools.awareness_tracker.domain.models import (
    MAX_CAMPAIGN_NAME_LENGTH,
    PhishingSimEvent,
    PhishingSimVendor,
)


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")
        self._conn.execute("PRAGMA foreign_keys = ON")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def service() -> AwarenessService:
    repo = AwarenessRepository(db=_InMemoryDB())
    return AwarenessService(repository=repo)


NOW = datetime(2026, 5, 16, 8, 0, tzinfo=UTC)


def _make_event(
    *,
    name: str = "Q2 2026",
    vendor: PhishingSimVendor = PhishingSimVendor.KNOWBE4,
    run_date: datetime = NOW,
    target_count: int = 10,
    click_count: int = 2,
    report_count: int = 5,
    training_assigned: bool = False,
    custom_vendor_label: str = "",
) -> PhishingSimEvent:
    return PhishingSimEvent(
        id=None,
        name=name,
        vendor=vendor,
        run_date=run_date,
        target_count=target_count,
        click_count=click_count,
        report_count=report_count,
        training_assigned=training_assigned,
        custom_vendor_label=custom_vendor_label,
    )


# ---------------------------------------------------------------------------
# Domain-Validierung
# ---------------------------------------------------------------------------


class TestPhishingSimEventDomain:
    def test_minimal_valid(self) -> None:
        event = _make_event()
        assert event.click_rate == 20.0
        assert event.report_rate == 50.0

    def test_leerer_name_wirft(self) -> None:
        with pytest.raises(ValueError, match="name"):
            _make_event(name="   ")

    def test_name_zu_lang_wirft(self) -> None:
        with pytest.raises(ValueError, match="name"):
            _make_event(name="x" * (MAX_CAMPAIGN_NAME_LENGTH + 1))

    def test_target_unter_eins_wirft(self) -> None:
        with pytest.raises(ValueError, match="target_count"):
            _make_event(target_count=0)

    def test_click_groesser_target_wirft(self) -> None:
        with pytest.raises(ValueError, match="click_count"):
            _make_event(target_count=10, click_count=11)

    def test_negative_clicks_werfen(self) -> None:
        with pytest.raises(ValueError, match="click_count"):
            _make_event(click_count=-1)

    def test_negative_reports_werfen(self) -> None:
        with pytest.raises(ValueError, match="report_count"):
            _make_event(report_count=-1)

    def test_report_kann_target_uebersteigen(self) -> None:
        # Reports koennen ueber 100% gehen (z.B. wenn Mitarbeiter eine
        # weitergeleitete Mail melden).
        event = _make_event(target_count=10, click_count=0, report_count=15)
        assert event.report_rate == 150.0

    def test_custom_vendor_ohne_label_wirft(self) -> None:
        with pytest.raises(ValueError, match="custom_vendor_label"):
            _make_event(
                vendor=PhishingSimVendor.CUSTOM,
                custom_vendor_label="   ",
            )

    def test_non_custom_loescht_label_leise(self) -> None:
        event = _make_event(
            vendor=PhishingSimVendor.KNOWBE4,
            custom_vendor_label="Unrelated",
        )
        # Datenhygiene: Label wird auf "" normalisiert, kein Wurf.
        assert event.custom_vendor_label == ""

    def test_click_rate_zero(self) -> None:
        event = _make_event(target_count=10, click_count=0)
        assert event.click_rate == 0.0

    def test_click_rate_volle_quote(self) -> None:
        event = _make_event(target_count=10, click_count=10)
        assert event.click_rate == 100.0

    def test_display_vendor_label_standard(self) -> None:
        event = _make_event(vendor=PhishingSimVendor.SOSAFE)
        assert "sosafe" in event.display_vendor_label.lower()

    def test_display_vendor_label_custom(self) -> None:
        event = _make_event(
            vendor=PhishingSimVendor.CUSTOM,
            custom_vendor_label="Hauseigene IT-Sim",
        )
        assert event.display_vendor_label == "Hauseigene IT-Sim"


class TestPhishingSimVendor:
    def test_from_value_bekannt(self) -> None:
        assert (
            PhishingSimVendor.from_value("knowbe4")
            is PhishingSimVendor.KNOWBE4
        )

    def test_from_value_unbekannt_faellt_auf_custom(self) -> None:
        assert (
            PhishingSimVendor.from_value("dings")
            is PhishingSimVendor.CUSTOM
        )


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class TestPhishingSimRepository:
    def test_add_und_get_roundtrip(
        self, service: AwarenessService
    ) -> None:
        event = service.add_phishing_sim(
            name="Q2 2026",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=10,
            click_count=2,
            report_count=5,
        )
        assert event.id is not None
        fetched = service.get_phishing_sim(event.id)
        assert fetched is not None
        assert fetched.name == "Q2 2026"
        assert fetched.vendor is PhishingSimVendor.KNOWBE4

    def test_list_sortiert_neueste_zuerst(
        self, service: AwarenessService
    ) -> None:
        service.add_phishing_sim(
            name="Alt",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW - timedelta(days=180),
            target_count=10,
            click_count=2,
        )
        service.add_phishing_sim(
            name="Neu",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=10,
            click_count=1,
        )
        events = service.list_phishing_sims()
        assert [e.name for e in events] == ["Neu", "Alt"]

    def test_update(self, service: AwarenessService) -> None:
        from dataclasses import replace  # noqa: PLC0415

        event = service.add_phishing_sim(
            name="Original",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=10,
            click_count=2,
        )
        updated = replace(event, name="Updated", click_count=5)
        service.update_phishing_sim(updated)
        refetched = service.get_phishing_sim(event.id)  # type: ignore[arg-type]
        assert refetched is not None
        assert refetched.name == "Updated"
        assert refetched.click_count == 5

    def test_update_ohne_id_wirft(self, service: AwarenessService) -> None:
        with pytest.raises(ValueError, match="id"):
            service.update_phishing_sim(_make_event())

    def test_update_unbekannte_id_wirft(
        self, service: AwarenessService
    ) -> None:
        from dataclasses import replace  # noqa: PLC0415

        ghost = replace(_make_event(), id=9999)
        with pytest.raises(ValueError, match="9999"):
            service.update_phishing_sim(ghost)

    def test_delete_hit(self, service: AwarenessService) -> None:
        event = service.add_phishing_sim(
            name="x",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=5,
            click_count=1,
        )
        assert service.delete_phishing_sim(event.id) is True  # type: ignore[arg-type]
        assert service.get_phishing_sim(event.id) is None  # type: ignore[arg-type]

    def test_delete_miss(self, service: AwarenessService) -> None:
        assert service.delete_phishing_sim(9999) is False


# ---------------------------------------------------------------------------
# KPI-Aggregation
# ---------------------------------------------------------------------------


class TestPhishingSimKpi:
    def test_leer_ist_empty(self, service: AwarenessService) -> None:
        kpi = service.compute_phishing_sim_kpi()
        assert kpi.is_empty is True
        assert kpi.campaign_count == 0
        assert kpi.latest_click_rate is None
        assert kpi.trend_delta_percent is None

    def test_einzel_kampagne_kein_trend(
        self, service: AwarenessService
    ) -> None:
        service.add_phishing_sim(
            name="x",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=10,
            click_count=2,
        )
        kpi = service.compute_phishing_sim_kpi()
        assert kpi.campaign_count == 1
        assert kpi.avg_click_rate == 20.0
        assert kpi.latest_click_rate == 20.0
        assert kpi.trend_delta_percent is None

    def test_gewichteter_avg(self, service: AwarenessService) -> None:
        # 100-Personen-Kampagne mit 10 % vs 5-Personen-Kampagne mit 40 %.
        service.add_phishing_sim(
            name="Gross",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW - timedelta(days=180),
            target_count=100,
            click_count=10,
        )
        service.add_phishing_sim(
            name="Klein",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=5,
            click_count=2,
        )
        kpi = service.compute_phishing_sim_kpi()
        # Gewichtet: (10 + 2) / (100 + 5) * 100 = 12 / 105 * 100 ≈ 11.43
        assert abs(kpi.avg_click_rate - (12.0 / 105.0 * 100.0)) < 0.01

    def test_trend_besser(self, service: AwarenessService) -> None:
        service.add_phishing_sim(
            name="Alt 1",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW - timedelta(days=180),
            target_count=10,
            click_count=5,
        )
        service.add_phishing_sim(
            name="Alt 2",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW - timedelta(days=90),
            target_count=10,
            click_count=5,
        )
        service.add_phishing_sim(
            name="Neu",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=10,
            click_count=1,
        )
        kpi = service.compute_phishing_sim_kpi()
        # Neueste: 10%, vorherige Avg: 50%. Delta: 10 - 50 = -40 (besser).
        assert kpi.trend_delta_percent is not None
        assert kpi.trend_delta_percent < 0
        assert "besser" in kpi.trend_label

    def test_trend_schlechter(self, service: AwarenessService) -> None:
        service.add_phishing_sim(
            name="Alt",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW - timedelta(days=90),
            target_count=10,
            click_count=1,
        )
        service.add_phishing_sim(
            name="Neu",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=10,
            click_count=5,
        )
        kpi = service.compute_phishing_sim_kpi()
        # Neueste: 50%, vorherige: 10%. Delta: +40 (schlechter).
        assert kpi.trend_delta_percent is not None
        assert kpi.trend_delta_percent > 0
        assert "schlechter" in kpi.trend_label

    def test_trend_stabil(self, service: AwarenessService) -> None:
        service.add_phishing_sim(
            name="Alt",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW - timedelta(days=90),
            target_count=10,
            click_count=2,
        )
        service.add_phishing_sim(
            name="Neu",
            vendor=PhishingSimVendor.KNOWBE4,
            run_date=NOW,
            target_count=10,
            click_count=2,
        )
        kpi = service.compute_phishing_sim_kpi()
        # Beide 20% → Delta 0 → "stabil"
        assert kpi.trend_delta_percent is not None
        assert abs(kpi.trend_delta_percent) < 0.01
        assert "stabil" in kpi.trend_label


class TestPhishingSimKpiLabels:
    def test_trend_label_none(self) -> None:
        kpi = PhishingSimKpi(
            campaign_count=1,
            avg_click_rate=10.0,
            avg_report_rate=5.0,
            latest_click_rate=10.0,
            trend_delta_percent=None,
        )
        assert kpi.trend_label == "—"

    def test_trend_label_unter_eins_ist_stabil(self) -> None:
        kpi = PhishingSimKpi(
            campaign_count=2,
            avg_click_rate=10.0,
            avg_report_rate=5.0,
            latest_click_rate=10.0,
            trend_delta_percent=0.5,
        )
        assert "stabil" in kpi.trend_label
