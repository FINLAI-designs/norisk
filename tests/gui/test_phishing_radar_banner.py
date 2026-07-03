"""
test_phishing_radar_banner — GUI-Smoke-Tests fuer den
``PhishingRadarBanner``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.cyber_dashboard.domain.models import (
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
)
from tools.mainpage.gui.phishing_radar_banner import (
    _BANNER_HOEHE,
    PhishingRadarBanner,
)
from tools.mainpage.gui.phishing_radar_data import (
    BannerDaten,
    PhishingRadarViewModel,
)


class _FakeViewModel(PhishingRadarViewModel):
    def __init__(self, daten: BannerDaten) -> None:
        super().__init__(None)
        self._daten = daten

    def banner_daten(self) -> BannerDaten:  # type: ignore[override]
        return self._daten


def _meldung(guid: str) -> CyberMeldung:
    return CyberMeldung(
        titel=f"Phishing-Angriff {guid}",
        beschreibung="Test",
        url=f"https://example.com/{guid}",
        quelle=QuelleTyp.WATCHLIST_AT,
        schweregrad=Schweregrad.HOCH,
        veroeffentlicht=datetime.now(UTC) - timedelta(hours=1),
        guid=guid,
    )


@pytest.mark.usefixtures("app")
class TestPhishingRadarBanner:
    def test_banner_ist_expandierende_karte(self) -> None:
        """ AP3: Mindesthoehe statt Fixhoehe — die Karte waechst
        in der rechten Homescreen-Spalte mit."""
        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(items=[], neue_24h=0, ungelesen=0, gesamt=0, bereit=True)
        ))
        assert banner.minimumHeight() == _BANNER_HOEHE
        # Kein Fixhoehen-Deckel mehr (QWIDGETSIZE_MAX = 16777215)
        assert banner.maximumHeight() > 10_000

    def test_banner_rendert_bis_zu_sechs_items(self) -> None:
        """ AP3: 6 statt 2 Meldungen sichtbar."""
        items = [_meldung(str(i)) for i in range(8)]
        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(items=items, neue_24h=8, ungelesen=8, gesamt=8, bereit=True)
        ))
        assert banner._items_layout.count() == 6  # noqa: SLF001

    def test_placeholder_bei_unbereitem_service(self) -> None:
        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(items=[], neue_24h=0, ungelesen=0, gesamt=0, bereit=False)
        ))
        # Pill muss bei nicht-bereit hidden sein.
        assert not banner._pill.isVisible() or not banner._pill.text()

    def test_pill_zeigt_konkreten_counter(self) -> None:
        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(items=[_meldung("1")], neue_24h=12, ungelesen=5, gesamt=23, bereit=True)
        ))
        assert "12" in banner._pill.text()
        assert "geschützt" in banner._pill.text()

    def test_cta_zeigt_gesamt_count(self) -> None:
        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(items=[], neue_24h=0, ungelesen=2, gesamt=23, bereit=True)
        ))
        assert "23" in banner._oeffnen_btn.text()
        assert "2 ungelesen" in banner._ungelesen_lbl.text()

    def test_viewmodel_vorlimitierte_items_bleiben_unangetastet(self) -> None:
        """Vom ViewModel vorgefilterte Listen rendert der Banner 1:1
 AP3: das harte Render-Cap liegt bei 6, s. eigener Test)."""
        meldungen = [_meldung(str(i)) for i in range(50)]
        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(
                items=meldungen[:2],
                neue_24h=50, ungelesen=50, gesamt=50, bereit=True
            )
        ))
        # Items-Layout zaehlen — die Children sind die Item-Rows.
        item_widgets = [
            banner._items_layout.itemAt(i).widget()
            for i in range(banner._items_layout.count())
        ]
        assert len(item_widgets) == 2

    def test_notfall_link_existiert(self) -> None:
        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(items=[], neue_24h=0, ungelesen=0, gesamt=0, bereit=True)
        ))
        assert banner._notfall_btn.text() == "Schon reingefallen?"

    def test_tooltip_glossar_t01(self) -> None:
        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(items=[], neue_24h=0, ungelesen=0, gesamt=0, bereit=True)
        ))
        tt = banner._header.toolTip()
        assert "Betrugs-Mails" in tt
        assert "Passwörter" in tt


class TestSnoozeBisMorgen:
    """Snooze rechnet 06:00 **lokale** Zeit, nicht 06:00 UTC P1)."""

    def test_liefert_lokale_sechs_uhr_als_utc(self) -> None:
        from tools.mainpage.gui.phishing_inbox_list import snooze_bis_morgen

        bis = snooze_bis_morgen()
        assert bis.tzinfo == UTC
        # Zurueck in lokale Zeit konvertiert muss 06:00 herauskommen —
        # unabhaengig von der Zeitzone des Test-Runners.
        lokal = bis.astimezone()
        assert (lokal.hour, lokal.minute, lokal.second) == (6, 0, 0)

    def test_liegt_in_der_zukunft(self) -> None:
        from tools.mainpage.gui.phishing_inbox_list import snooze_bis_morgen

        assert snooze_bis_morgen() > datetime.now(UTC)


def _boeser_titel_meldung() -> CyberMeldung:
    """CyberMeldung mit HTML-Tracking-Pixel im Titel (untrusted Feed)."""
    return CyberMeldung(
        titel='Warnung <img src="http://tracker.evil/p.png">',
        beschreibung="Body",
        url="https://example.com/x",
        quelle=QuelleTyp.WATCHLIST_AT,
        schweregrad=Schweregrad.HOCH,
        veroeffentlicht=datetime.now(UTC) - timedelta(hours=1),
        guid="evil-1",
    )


@pytest.mark.usefixtures("app")
class TestFeedTitelXssHaertung:
    """ Review-P1: Feed-Titel ist untrusted und darf nirgends als
    Rich-Text gerendert werden (sonst Tracking-Pixel via <img>-Markup)."""

    def test_banner_titel_ist_plaintext(self) -> None:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QLabel

        banner = PhishingRadarBanner(view_model=_FakeViewModel(
            BannerDaten(
                items=[_boeser_titel_meldung()],
                neue_24h=1, ungelesen=1, gesamt=1, bereit=True,
            )
        ))
        row = banner._items_layout.itemAt(0).widget()
        titel_labels = [
            lbl for lbl in row.findChildren(QLabel)
            if "img" in lbl.text().lower()
        ]
        assert titel_labels, "Titel-Label mit <img> nicht gefunden"
        for lbl in titel_labels:
            assert lbl.textFormat() == Qt.TextFormat.PlainText

    def test_inbox_tooltip_escaped_html(self) -> None:
        from PySide6.QtCore import Qt

        from tools.mainpage.gui.phishing_inbox_list import PhishingItemModel

        model = PhishingItemModel()
        model.setze_meldungen([_boeser_titel_meldung()], set())
        tooltip = model.data(model.index(0, 0), Qt.ItemDataRole.ToolTipRole)
        assert "<img" not in tooltip
        assert "&lt;img" in tooltip
