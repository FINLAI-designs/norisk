"""
test_briefing_consumer_section — GUI-Tests für die 3. Briefing-Sektion.

Abdeckung (Variante B, 2-ueber-1 Layout):
- _ConsumerZeile zeigt Quelle + Produkt + Datum + Beschreibung.
- Unbekannte Quelle fällt auf ACCENT_DIM zurück (kein Crash).
- _ConsumerSektion ``zeige_eintraege`` rendert mehrere Zeilen.
- BriefingTab ``aktualisiere`` befuellt die 3 Sektionen aus dem Cache-Dict.
- Leeres Briefing-Dict zeigt Empty-State in allen drei Sektionen.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture
def stub_service():
    svc = MagicMock()
    svc.lade_meldungen.return_value = []
    svc.lade_cves_gefiltert.return_value = []
    svc.lade_techstack.return_value = []
    return svc


class TestConsumerZeile:
    def test_zeigt_quell_badge(self, qtbot, app) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import _ConsumerZeile

        z = _ConsumerZeile(
            produkt="Chrome (Desktop)",
            quelle="Chrome",
            beschreibung="Stable Update 123.",
            datum="2026-04-20",
        )
        qtbot.addWidget(z)
        assert z._lbl_quelle.text() == "Chrome"
        assert z._lbl_produkt.text() == "Chrome (Desktop)"
        assert z._lbl_datum.text() == "2026-04-20"

    def test_ohne_datum_keine_datum_zeile(self, qtbot, app) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import _ConsumerZeile

        z = _ConsumerZeile(produkt="Firefox", quelle="Mozilla", beschreibung="Text")
        qtbot.addWidget(z)
        assert not hasattr(z, "_lbl_datum")

    def test_unbekannte_quelle_crasht_nicht(self, qtbot, app) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import _ConsumerZeile

        z = _ConsumerZeile(produkt="X", quelle="Unknown", beschreibung="Text")
        qtbot.addWidget(z)
        # Kein Crash bedeutet: Theme-Stylesheet wurde ohne Exception gesetzt.
        assert z.styleSheet() != ""


class TestConsumerSektion:
    def test_zeigt_mehrere_eintraege(self, qtbot, app) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import _ConsumerSektion

        s = _ConsumerSektion("Verbreitete Software")
        qtbot.addWidget(s)
        s.zeige_eintraege(
            [
                {
                    "produkt": "Windows 11",
                    "quelle": "MSRC",
                    "beschreibung": "Patch XY.",
                    "datum": "2026-04-15",
                },
                {
                    "produkt": "Chrome",
                    "quelle": "Chrome",
                    "beschreibung": "Stable Update.",
                    "datum": "2026-04-18",
                },
            ]
        )
        assert s._liste_layout.count() == 2


class TestBriefingTabDreiSektionen:
    def test_aktualisiere_mit_vollem_briefing(self, qtbot, app, stub_service) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import BriefingTab

        tab = BriefingTab(stub_service)
        qtbot.addWidget(tab)

        tab.aktualisiere(
            {
                "datum": "2026-04-21",
                "generiert_um": "12:00",
                "modell": "llama3.2",
                "techstack_leer": False,
                "techstack_eintraege": [
                    {
                        "produkt": "Python",
                        "cve_id": "CVE-2026-0001",
                        "beschreibung": "Beschreibung 1.",
                    }
                ],
                "allgemein_eintraege": [
                    {
                        "produkt": "NVD",
                        "cve_id": "CVE-2026-0002",
                        "beschreibung": "Beschreibung 2.",
                    }
                ],
                "consumer_eintraege": [
                    {
                        "produkt": "Windows 11",
                        "quelle": "MSRC",
                        "beschreibung": "Patch XY.",
                        "datum": "2026-04-15",
                    }
                ],
            }
        )

        # Techstack-Spalte + Consumer-Sektion haben je einen Eintrag. Die
        # fruehere "Allgemein"-Spalte ist durch die Phishing-Sektion ersetzt
        # (c1); ohne Phishing-Daten zeigt deren KMU-Gruppe den Hinweis (1 Label).
        assert tab._spalte_techstack._liste_layout.count() == 1
        assert tab._sektion_phishing._gruppe_kmu._liste_layout.count() == 1
        assert tab._sektion_consumer._liste_layout.count() == 1

    def test_aktualisiere_ohne_consumer_eintraege_zeigt_hinweis(
        self, qtbot, app, stub_service
    ) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import BriefingTab

        tab = BriefingTab(stub_service)
        qtbot.addWidget(tab)
        tab.aktualisiere(
            {
                "techstack_leer": False,
                "techstack_eintraege": [],
                "allgemein_eintraege": [],
                "consumer_eintraege": [],
            }
        )
        # Consumer-Sektion zeigt Hinweis (ein Label-Eintrag).
        assert tab._sektion_consumer._liste_layout.count() == 1

    def test_leeres_briefing_zeigt_empty_state_in_allen_drei(
        self, qtbot, app, stub_service
    ) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import BriefingTab

        tab = BriefingTab(stub_service)
        qtbot.addWidget(tab)
        tab.aktualisiere({})
        assert tab._spalte_techstack._liste_layout.count() == 1
        assert tab._sektion_phishing._gruppe_kmu._liste_layout.count() == 1
        assert tab._sektion_consumer._liste_layout.count() == 1

    def test_phishing_wird_trotz_cve_fehler_gezeigt(
        self, qtbot, app, stub_service
    ) -> None:
        """Review P2: scheitert das CVE-Briefing (_fehler), werden vorhandene
        Phishing-Warnungen trotzdem gerendert (nicht verworfen)."""
        from tools.cyber_dashboard.gui.briefing_tab import BriefingTab

        tab = BriefingTab(stub_service)
        qtbot.addWidget(tab)
        tab.aktualisiere(
            {
                "_fehler": "Timeout",
                "phishing_kmu": [
                    {"titel": "Fake-Rechnung", "beschreibung": "K.", "quelle": "Watchlist Internet"}
                ],
                "phishing_consumer": [],
            }
        )
        # Phishing-KMU-Gruppe hat den Eintrag (kein "Kein Briefing"-Hinweis).
        assert tab._sektion_phishing._gruppe_kmu._liste_layout.count() == 1

    def test_aktualisiere_rendert_phishing_in_zwei_gruppen(
        self, qtbot, app, stub_service
    ) -> None:
        """c1: phishing_kmu/phishing_consumer landen in den beiden Gruppen."""
        from tools.cyber_dashboard.gui.briefing_tab import BriefingTab

        tab = BriefingTab(stub_service)
        qtbot.addWidget(tab)
        tab.aktualisiere(
            {
                "techstack_eintraege": [],
                "techstack_leer": True,
                "consumer_eintraege": [],
                "phishing_kmu": [
                    {"titel": "Fake-Rechnung", "beschreibung": "K.", "quelle": "Watchlist Internet"}
                ],
                "phishing_consumer": [
                    {"titel": "Paket-SMS", "beschreibung": "C.", "quelle": "Mimikama"},
                    {"titel": "Bank-Mail", "beschreibung": "C2.", "quelle": "Mimikama"},
                ],
            }
        )
        assert tab._sektion_phishing._gruppe_kmu._liste_layout.count() == 1
        assert tab._sektion_phishing._gruppe_consumer._liste_layout.count() == 2
