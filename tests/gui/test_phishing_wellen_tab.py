"""GUI-Tests fuer PhishingWellenTab (Tab 2 /).

Deterministisch (``auto_load=False``): Rendering + Toggle ohne Worker-Thread.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tools.cyber_dashboard.domain.models import CyberMeldung, QuelleTyp, Schweregrad
from tools.cyber_dashboard.gui.phishing_wellen_tab import (
    PhishingWellenTab,
    _PhishingCard,
    _quelle_label,
)

pytestmark = pytest.mark.gui


def _m(
    titel: str = "Fake-Rechnung", quelle: QuelleTyp = QuelleTyp.WATCHLIST_AT
) -> CyberMeldung:
    return CyberMeldung(
        titel=titel,
        beschreibung="Betrueger versenden gefaelschte Nachrichten.",
        url="http://example.invalid/x",
        quelle=quelle,
        schweregrad=Schweregrad.MITTEL,
        veroeffentlicht=datetime(2026, 6, 29, tzinfo=UTC),
    )


def test_quelle_label_und_land() -> None:
    name, land = _quelle_label(QuelleTyp.WATCHLIST_AT)
    assert name == "Watchlist Internet"
    assert land == "AT"
    # International -> INT-Fallback
    _, land_int = _quelle_label(QuelleTyp.KREBS)
    assert land_int == "INT"


def test_render_karten_und_ueberblick(qtbot, app) -> None:
    tab = PhishingWellenTab(service=object(), auto_load=False)
    qtbot.addWidget(tab)
    tab.render([_m("CEO-Fraud")], [_m("Bank-SMS")])
    assert len(tab.findChildren(_PhishingCard)) == 2
    assert "2 aktuelle" in tab._lbl_ueberblick.text()


def test_leerer_zustand(qtbot, app) -> None:
    tab = PhishingWellenTab(service=object(), auto_load=False)
    qtbot.addWidget(tab)
    tab.render([], [])
    assert tab.findChildren(_PhishingCard) == []
    assert "keine phishing-wellen" in tab._lbl_ueberblick.text().lower()


def test_ki_trend_label(qtbot, app) -> None:
    tab = PhishingWellenTab(service=object(), auto_load=False)
    qtbot.addWidget(tab)
    tab._on_trend_fertig("Fake-Rechnungen haeufen sich bei Unternehmen.")
    assert "Fake-Rechnungen" in tab._lbl_ki_trend.text()
    assert not tab._lbl_ki_trend.isHidden()
    # Leerer Trend (Ollama nicht erreichbar) -> Hinweis statt Stille.
    tab._on_trend_fertig("")
    assert "nicht verfügbar" in tab._lbl_ki_trend.text()


def test_toggle_unternehmen_filtert(qtbot, app) -> None:
    tab = PhishingWellenTab(service=object(), auto_load=False)
    qtbot.addWidget(tab)
    tab.render([_m("KMU-Welle")], [_m("Privat-1"), _m("Privat-2")])
    assert len(tab.findChildren(_PhishingCard)) == 3
    # Index 1 = "Unternehmen" -> nur KMU-Karten
    tab._combo.setCurrentIndex(1)
    qtbot.waitUntil(lambda: len(tab.findChildren(_PhishingCard)) == 1, timeout=2000)
