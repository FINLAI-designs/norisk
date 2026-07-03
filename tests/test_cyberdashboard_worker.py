"""
test_cyberdashboard_worker — Tests für _LadeThread Worker-Logik.

Prüft:
  1. Fortschritts-Signale werden emittiert und Prozent steigt monoton
  2. Erfolgreiche Daten werden über Signals weitergegeben
  3. Fehler in Service-Aufrufen → leere Daten emittiert, kein Crash
  4. Fortschritt endet immer bei 100 %
  5. fertig-Signal wird immer emittiert (auch bei Fehlern)

Neue Fortschrittsverteilung (nach Entfernen von Videos und KI-Auto-Briefing):
  RSS-Feeds: 0–40 %
  CVE-Datenbank: 40–80 %
  Statistiken: 80–100 %

Alle Tests verwenden Mock-Daten — kein Netzwerk, keine DB.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tools.cyber_dashboard.gui.dashboard_widget import _LadeThread

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_service():
    """DashboardService-Mock mit leeren Standardrückgaben."""
    svc = MagicMock()
    svc.lade_meldungen.return_value = []
    svc.lade_cves.return_value = None
    svc.zaehle_statistiken.return_value = {}
    svc.lade_cves_gefiltert.return_value = []
    return svc


@pytest.fixture
def thread(mock_service):
    """_LadeThread mit Mock-Service."""
    t = _LadeThread(mock_service)
    yield t
    if t.isRunning():
        t.quit()
        t.wait(2000)


# ---------------------------------------------------------------------------
# 1. Fortschritts-Signale
# ---------------------------------------------------------------------------


class TestFortschrittsSignale:
    """Stellt sicher dass fortschritt korrekt emittiert wird."""

    def test_fortschritt_wird_emittiert(self, qtbot, thread):
        """fortschritt-Signal wird mindestens einmal emittiert."""
        werte: list[int] = []
        thread.fortschritt.connect(lambda p, _t: werte.append(p))

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert len(werte) > 0, "fortschritt muss mindestens einmal emittiert werden"

    def test_fortschritt_endet_bei_100(self, qtbot, thread):
        """Der letzte fortschritt-Wert muss 100 sein."""
        werte: list[int] = []
        thread.fortschritt.connect(lambda p, _t: werte.append(p))

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert werte[-1] == 100, f"Letzter Fortschritt muss 100 sein, war {werte[-1]}"

    def test_fortschritt_steigt_monoton(self, qtbot, thread):
        """Fortschrittswerte dürfen nie kleiner werden."""
        werte: list[int] = []
        thread.fortschritt.connect(lambda p, _t: werte.append(p))

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        for i in range(1, len(werte)):
            assert werte[i] >= werte[i - 1], (
                f"Fortschritt fiel von {werte[i - 1]} auf {werte[i]} (Index {i})"
            )

    def test_fortschritt_schritt_text_nicht_leer(self, qtbot, thread):
        """Jeder fortschritt-Emit muss einen nicht-leeren Schritt-Text liefern."""
        texte: list[str] = []
        thread.fortschritt.connect(lambda _p, t: texte.append(t))

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert all(t.strip() for t in texte), "Kein Schritt-Text darf leer sein"

    def test_fortschritt_rss_phase_endet_bei_40(self, qtbot, thread):
        """Nach RSS-Laden muss der Fortschritt mindestens 40 % erreichen."""
        werte: list[int] = []
        thread.fortschritt.connect(lambda p, _t: werte.append(p))

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert max(werte) >= 40, "RSS-Phase muss mindestens 40 % erreichen"

    def test_fortschritt_cve_phase_endet_bei_80(self, qtbot, thread):
        """Nach CVE-Laden muss der Fortschritt mindestens 80 % erreichen."""
        werte: list[int] = []
        thread.fortschritt.connect(lambda p, _t: werte.append(p))

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert max(werte) >= 80, "CVE-Phase muss mindestens 80 % erreichen"


# ---------------------------------------------------------------------------
# 2. Daten-Signale bei Erfolg
# ---------------------------------------------------------------------------


class TestDatensignaleErfolg:
    """Prüft dass Daten korrekt über Signals weitergegeben werden."""

    def test_meldungen_geladen_emittiert_daten(self, qtbot, mock_service):
        """Geladene Meldungen werden über meldungen_geladen emittiert."""
        from datetime import UTC, datetime

        from tools.cyber_dashboard.domain.models import (
            CyberMeldung,
            QuelleTyp,
            Schweregrad,
        )

        fake_meldung = CyberMeldung(
            guid="guid-1",
            titel="Test-Warnung",
            beschreibung="Beschreibung",
            url="https://example.com",
            quelle=QuelleTyp.CERT_AT,
            schweregrad=Schweregrad.HOCH,
            veroeffentlicht=datetime.now(UTC),
        )
        mock_service.lade_meldungen.return_value = [fake_meldung]

        thread = _LadeThread(mock_service)
        empfangen: list = []
        thread.meldungen_geladen.connect(empfangen.extend)

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert len(empfangen) == 1
        assert empfangen[0].guid == "guid-1"

    def test_statistiken_geladen_emittiert_dict(self, qtbot, mock_service):
        """Statistiken werden als Dict emittiert."""
        mock_service.zaehle_statistiken.return_value = {"CRITICAL": 3, "HIGH": 7}

        thread = _LadeThread(mock_service)
        statistiken: list[dict] = []
        thread.statistiken_geladen.connect(statistiken.append)

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert statistiken
        assert statistiken[-1].get("CRITICAL") == 3
        assert statistiken[-1].get("HIGH") == 7

    def test_kein_videos_signal_vorhanden(self):
        """_LadeThread hat kein videos_geladen-Signal mehr."""
        assert not hasattr(_LadeThread, "videos_geladen"), (
            "videos_geladen-Signal wurde entfernt — darf nicht mehr existieren"
        )

    def test_kein_briefing_signal_vorhanden(self):
        """_LadeThread hat kein briefing_geladen-Signal mehr."""
        assert not hasattr(_LadeThread, "briefing_geladen"), (
            "briefing_geladen-Signal wurde entfernt — darf nicht mehr existieren"
        )


# ---------------------------------------------------------------------------
# 3. Fehlerbehandlung — kein Crash, leere Daten emittiert
# ---------------------------------------------------------------------------


class TestFehlerbehandlung:
    """Service-Fehler dürfen den Thread nicht crashen."""

    def test_meldungen_fehler_emittiert_leer(self, qtbot, mock_service):
        """Exception in lade_meldungen → leere Liste emittiert, fertig folgt."""
        mock_service.lade_meldungen.side_effect = ConnectionError("Kein Netz")

        thread = _LadeThread(mock_service)
        meldungen: list = []
        thread.meldungen_geladen.connect(meldungen.extend)

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert meldungen == [], "Bei Fehler muss leere Liste emittiert werden"

    def test_statistiken_fehler_emittiert_leeres_dict(self, qtbot, mock_service):
        """Exception in zaehle_statistiken → leeres Dict emittiert."""
        mock_service.zaehle_statistiken.side_effect = RuntimeError("DB locked")

        thread = _LadeThread(mock_service)
        statistiken: list[dict] = []
        thread.statistiken_geladen.connect(statistiken.append)

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert statistiken == [{}]

    def test_alle_schritte_fehler_fertig_trotzdem_emittiert(self, qtbot, mock_service):
        """Auch wenn alle Schritte fehlschlagen wird fertig emittiert."""
        mock_service.lade_meldungen.side_effect = Exception("Alles kaputt")
        mock_service.lade_cves.side_effect = Exception("Alles kaputt")
        mock_service.zaehle_statistiken.side_effect = Exception("Alles kaputt")

        thread = _LadeThread(mock_service)

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()  # darf nicht hängenbleiben

    def test_fortschritt_endet_bei_100_auch_bei_fehlern(self, qtbot, mock_service):
        """Fortschritt endet bei 100 auch wenn alle Service-Calls scheitern."""
        mock_service.lade_meldungen.side_effect = Exception("Fehler")
        mock_service.zaehle_statistiken.side_effect = Exception("Fehler")

        thread = _LadeThread(mock_service)
        werte: list[int] = []
        thread.fortschritt.connect(lambda p, _t: werte.append(p))

        with qtbot.waitSignal(thread.fertig, timeout=10_000):
            thread.start()

        assert werte[-1] == 100, f"Fortschritt muss bei 100 enden, war {werte[-1]}"
