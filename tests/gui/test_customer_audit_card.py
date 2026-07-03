"""test_customer_audit_card — GUI: Kunden-Audit-Karte + Hero-Toggle-Folge).

Abdeckung:
    * ``CustomerAuditCard.set_data`` rendert Score/Firma/Risikostufe; ``None``
      → neutraler Leerzustand.
    * Sicherheits-Regression: ``firmenname`` wird als PlainText gerendert
      (Markup nicht interpretiert — Lehre/).
    * „Audit öffnen"-Button emittiert ``open_audit``.
    * Dashboard-Integration: Kunden-Subjekt mit Audit → Karte sichtbar
      (zusätzlich zum immer sichtbaren SELF-Einstiegs-Band); „Allgemein"
      → Karte ausgeblendet, Band bleibt; CTA routet ``navigate("customer_audit")``.

Sichtbarkeit wird über ``isHidden`` geprüft — das reflektiert die expliziten
``setVisible``-Aufrufe unabhängig davon, ob das Top-Level-Widget gezeigt wurde.

Author: Patrick Riederich
Version: 1.0-Folge)
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import Qt

from tools.norisk_dashboard.domain.models import (
    CustomerAuditSummary,
    DashboardData,
    ScoreSnapshot,
    TimeRange,
)

pytestmark = pytest.mark.gui


def _summary(firmenname: str = "Acme GmbH", risk: str = "Hoch") -> CustomerAuditSummary:
    return CustomerAuditSummary(
        subject_id="s1",
        firmenname=firmenname,
        overall_score=72.0,
        risk_level=risk,
        created_at=datetime(2026, 6, 1),
        audit_id="a1",
        audit_count=2,
    )


@pytest.mark.usefixtures("app")
class TestCustomerAuditCard:
    def _card(self, qtbot):
        from tools.norisk_dashboard.gui.customer_audit_card import CustomerAuditCard

        card = CustomerAuditCard()
        qtbot.addWidget(card)
        return card

    def test_set_data_renders_score(self, qtbot):
        card = self._card(qtbot)
        card.set_data(_summary())
        assert card._score.text() == "72"
        assert card._firma.text() == "Acme GmbH"
        assert "Hoch" in card._risk.text()
        assert "2 Audits" in card._meta.text()

    def test_set_data_none_is_empty_state(self, qtbot):
        card = self._card(qtbot)
        card.set_data(_summary())
        card.set_data(None)
        assert card._score.text() == "—"
        assert card._firma.text() == "—"
        assert card._risk.text() == ""

    def test_firmenname_is_plaintext(self, qtbot):
        # Sicherheits-Regression: Markup im Firmennamen wird NICHT interpretiert.
        card = self._card(qtbot)
        card.set_data(_summary(firmenname="<b>boom</b>"))
        assert card._firma.textFormat() == Qt.TextFormat.PlainText
        assert card._firma.text() == "<b>boom</b>"  # literal, nicht geparst

    def test_open_audit_signal_on_click(self, qtbot):
        card = self._card(qtbot)
        with qtbot.waitSignal(card.open_audit, timeout=500):
            card._open_btn.click()


def test_risk_color_mapping_covers_all_risk_levels():
    """Drift-Wächter (Review-P2): jede von ``score_to_risk_level`` erzeugte
    Stufe muss im Farb-Mapping liegen.

    Sonst zeigt die Karte eine kritische Stufe still neutral-blau
    (Risiko-Unterschätzung). Fängt eine Umbenennung der Stufen-Strings in
    ``customer_audit/domain`` im CI ab, bevor sie in der UI verschwindet.
    """
    from tools.customer_audit.domain.scoring_service import score_to_risk_level
    from tools.norisk_dashboard.gui.customer_audit_card import _RISK_FARBE

    for score in range(0, 101, 5):
        level = score_to_risk_level(float(score)).casefold()
        assert level in _RISK_FARBE, f"Risikostufe '{level}' (Score {score}) ohne Farbe"


def _data(customer_audit: CustomerAuditSummary | None) -> DashboardData:
    return DashboardData(
        time_range=TimeRange.WEEK,
        score=ScoreSnapshot(target="Allgemein"),
        generated=datetime(2026, 6, 4, 12, 0, 0),
        customer_audit=customer_audit,
    )


class _FakeAgg:
    """Aggregator-Fake: liefert ein customer_audit nur bei gewähltem Subjekt."""

    def __init__(self, customer_audit: CustomerAuditSummary | None = None) -> None:
        self._ca = customer_audit
        self.calls: list[tuple[str, str | None]] = []

    def subjects(self) -> list[tuple[str, str]]:
        return [("s1", "Acme GmbH")]

    def aggregate(self, time_range, target_name="Allgemein", *, subject_id=None):  # noqa: ANN001, ANN202
        self.calls.append((target_name, subject_id))
        return _data(self._ca if subject_id else None)


def _make_widget(qtbot, aggregator):
    from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

    w = NoRiskDashboardWidget(aggregator=aggregator, export_service=MagicMock())
    qtbot.addWidget(w)
    return w


@pytest.mark.usefixtures("app")
class TestDashboardCardToggle:
    def test_customer_subject_shows_card(self, qtbot):
        w = _make_widget(qtbot, _FakeAgg(customer_audit=_summary()))
        w._subject_selector.setCurrentIndex(1)  # Acme GmbH → refresh → _apply
        assert not w._customer_audit_card.isHidden()
        # Das SELF-Einstiegs-Band bleibt immer sichtbar — die
        # Kunden-Karte erscheint zusätzlich darunter (keine Exklusivität mehr).
        assert not w._cockpit_band.isHidden()

    def test_allgemein_hides_card_band_stays(self, qtbot):
        w = _make_widget(qtbot, _FakeAgg(customer_audit=_summary()))
        w.refresh()  # subject_id None → customer_audit None
        assert w._customer_audit_card.isHidden()
        assert not w._cockpit_band.isHidden()

    def test_cta_routes_navigate_to_customer_audit(self, qtbot):
        w = _make_widget(qtbot, _FakeAgg(customer_audit=_summary()))
        w._subject_selector.setCurrentIndex(1)
        with qtbot.waitSignal(w.navigate, timeout=500) as blocker:
            w._customer_audit_card.open_audit.emit()
        assert blocker.args == ["customer_audit"]
