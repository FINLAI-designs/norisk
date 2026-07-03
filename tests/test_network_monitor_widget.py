"""Tests für NetworkMonitorWidget.

Single-Tenant-OSS — kein Free/Pro-Gating mehr; alle Anteile
(Export, Suspicious-Highlighting, Bedrohungslisten-/Konversationen-Tab) sind
immer aktiv. Es gibt keinen Upgrade-Overlay und keinen ``pro_override`` mehr.

Der Worker wird im Test nicht gestartet (``auto_start_worker=False``), um keine
Hintergrund-Samples — insbesondere keinen Threat-Feed-Download — zu erzwingen.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tools.network_monitor.gui.network_monitor_widget import NetworkMonitorWidget


@pytest.fixture
def widget(qtbot):
    # auto_start_worker=False: keine echten Threads — insbesondere kein
    # Threat-Feed-Refresh-Worker, der sonst einen echten abuse.ch-Download
    # anstoßen würde (Regel 9: keine Netz-Deps im Test).
    w = NetworkMonitorWidget(auto_start_worker=False)
    qtbot.addWidget(w)
    return w


class TestGating:
    """: alle vormals Pro-gegateten Anteile sind jetzt immer aktiv."""

    def test_export_immer_aktiviert(self, widget) -> None:
        assert widget._export_btn.isEnabled() is True

    def test_highlighting_immer_aktiviert(self, widget) -> None:
        assert widget._conn_table._highlight_suspicious is True


class TestLifecycle:
    def test_widget_init_ohne_crash(self, qtbot) -> None:
        w = NetworkMonitorWidget(auto_start_worker=False)
        qtbot.addWidget(w)
        # Wenn wir hier ankommen, hat __init__ nicht gecrasht
        assert w is not None

    def test_stop_worker_idempotent(self, widget) -> None:
        widget.stop_worker()  # ohne gestarteten Worker kein Crash
        widget.stop_worker()  # zweiter Aufruf ebenfalls No-op
        assert widget._worker is None


class TestRefresherLifecycle:
    """: die periodischen UI-Refresher (Alter-Timer 1s, Konversationen 30s,
    Datenverbrauch 24h-GROUP-BY 30s) muessen beim Tab-Verlassen anhalten und beim
    Wieder-Betreten neu starten — sonst laeuft DB-I/O im UI-Thread auf einem
    anderen Tab weiter (S5a-Zusage, Freeze-Linie/)."""

    @staticmethod
    def _timers_active(w) -> tuple[bool, bool, bool]:
        return (
            w._update_age_timer.isActive(),
            w._conversation_tab._timer.isActive(),
            w._traffic_view._refresh_timer.isActive(),
        )

    def test_init_startet_alle_refresher(self, widget) -> None:
        assert self._timers_active(widget) == (True, True, True)

    def test_stop_worker_haelt_alle_refresher_an(self, widget) -> None:
        widget.stop_worker()  # Tab verlassen
        assert self._timers_active(widget) == (False, False, False)

    def test_start_worker_nimmt_refresher_wieder_auf(self, widget, monkeypatch) -> None:
        # _start_worker stubben: kein echter Worker-Thread / Threat-Feed-Download
        # (Regel 9). Der Stub setzt _worker wie der echte Start, damit der volle
        # start_worker-Pfad durchlaeuft (Early-Return-Check -> _start_worker ->
        # _resume_ui_refreshers) und der Test die Verdrahtung wirklich prueft.
        widget.stop_worker()
        assert self._timers_active(widget) == (False, False, False)

        def _fake_start() -> None:
            widget._worker = MagicMock()

        monkeypatch.setattr(widget, "_start_worker", _fake_start)
        widget.start_worker()  # Tab wieder betreten
        assert self._timers_active(widget) == (True, True, True)

    def test_start_worker_bei_laufendem_worker_kein_doppel_resume(self, widget) -> None:
        # Early-Return: laeuft bereits ein Worker, darf start_worker die
        # angehaltenen Refresher NICHT erneut anfassen (kein Doppel-Resume).
        widget.stop_worker()
        widget._worker = MagicMock()  # simuliert bereits laufenden Worker
        widget.start_worker()  # muss frueh zurueckkehren (worker is not None)
        assert self._timers_active(widget) == (False, False, False)
        widget._worker = None  # Fixture-Teardown sauber halten


class TestAnomalyWiring:
    """ F-E: Worker-Signal → Alert-Tab + Chart-Marker + Tab-Zaehler."""

    def _make(self, qtbot) -> NetworkMonitorWidget:
        # auto_start_worker=False: keine echten Threads — wir rufen die Slots direkt.
        w = NetworkMonitorWidget(auto_start_worker=False)
        qtbot.addWidget(w)
        return w

    def test_anomalien_aktualisieren_tab_marker_und_zaehler(self, qtbot) -> None:
        from tools.network_monitor.domain.models import (
            Anomaly,
            AnomalySeverity,
            AnomalyType,
        )

        w = self._make(qtbot)
        anomalies = [
            Anomaly(
                anomaly_type=AnomalyType.SINGLE_IP,
                severity=AnomalySeverity.MEDIUM,
                pid=1,
                process_name="a",
                value_bytes=2,
                threshold_bytes=1,
                remote_ip="1.1.1.1",
            ),
            Anomaly(
                anomaly_type=AnomalyType.VOLUME_SPIKE,
                severity=AnomalySeverity.HIGH,
                pid=2,
                process_name="b",
                value_bytes=4,
                threshold_bytes=1,
            ),
        ]
        w._on_anomalies_detected(anomalies)

        assert w._alert_tab.anomaly_count == 2
        # Schwerste Anomalie (HIGH) bestimmt den vorgemerkten Chart-Marker.
        assert w._pending_marker == AnomalyType.VOLUME_SPIKE
        assert "(2)" in w._tabs.tabText(w._alert_tab_index)

    def test_stats_update_konsumiert_marker_genau_einmal(self, qtbot) -> None:
        from tools.network_monitor.domain.models import AnomalyType

        w = self._make(qtbot)
        w._pending_marker = AnomalyType.VOLUME_SPIKE
        # Leeres Stats-Dict reicht (up=down=0); der Marker wird konsumiert.
        w._on_stats_updated({})
        assert w._pending_marker is None

    def test_keine_anomalien_titel_ohne_zaehler(self, qtbot) -> None:
        w = self._make(qtbot)
        w._on_anomalies_detected([])
        assert w._pending_marker is None
        assert w._tabs.tabText(w._alert_tab_index) == "Auffälligkeiten"


class TestThreatListTabWiring:
    """ F-D-GUI: Bedrohungslisten-Tab (immer aktiv) + Signal → Checker."""

    def _tab_texts(self, w) -> list[str]:
        return [w._tabs.tabText(i) for i in range(w._tabs.count())]

    def test_hat_bedrohungslisten_tab(self, widget) -> None:
        assert widget._threat_list_tab is not None
        assert "Bedrohungslisten" in self._tab_texts(widget)

    def test_whitelist_changed_aktualisiert_checker(self, widget) -> None:
        import ipaddress

        checker = widget._checker
        assert checker is not None
        before = checker.entry_count()
        widget._on_whitelist_changed([ipaddress.ip_network("9.9.9.9")])
        assert checker.whitelist_count() == 1
        # Einträge bleiben unangetastet (nur Whitelist getauscht)
        assert checker.entry_count() == before

    def test_entries_refreshed_aktualisiert_checker(self, widget) -> None:
        import ipaddress

        checker = widget._checker
        assert checker is not None
        widget._on_feed_entries_refreshed(
            [(ipaddress.ip_network("203.0.113.7"), "feed")],
            [ipaddress.ip_network("10.0.0.0/8")],
        )
        assert checker.is_suspicious("203.0.113.7") == (True, "feed")
        assert checker.whitelist_count() == 1


class TestConversationTabWiring:
    """ Phase 5: Konversationen-Tab (immer aktiv)."""

    def _tab_texts(self, w) -> list[str]:
        return [w._tabs.tabText(i) for i in range(w._tabs.count())]

    def test_hat_konversationen_tab(self, widget) -> None:
        assert widget._conversation_tab is not None
        assert "Konversationen" in self._tab_texts(widget)


class TestToolFailOpen:
    """: create_widget baut die History-Repos jetzt fuer alle — bei
    KeyManager-Defekt (Corrupt/Permission/NotInitialized) muss es fail-open
    bleiben (repository=None), nicht propagieren. KeyManagerError erbt NICHT von
    OSError/RuntimeError, daher muss das except sie explizit fangen (Review-P2).
    NetworkMonitorWidget wird gestubbt, damit kein Worker/Netz-Call startet.
    """

    def test_create_widget_fail_open_bei_keymanager_fehler(self, monkeypatch) -> None:
        import tools.network_monitor.data.connection_repository as cr
        import tools.network_monitor.data.process_traffic_repository as ptr
        import tools.network_monitor.gui.network_monitor_widget as nmw
        from core.database.key_manager import KeyManagerCorruptError
        from tools.network_monitor.tool import NetworkMonitorTool

        def _boom(*_a, **_k):
            raise KeyManagerCorruptError("korrupter KeyManager")

        monkeypatch.setattr(cr, "ConnectionHistoryRepository", _boom)
        monkeypatch.setattr(ptr, "ProcessTrafficRepository", _boom)

        captured: dict[str, object] = {}

        def _stub(parent=None, repository=None, process_traffic_repo=None):
            captured["repository"] = repository
            captured["traffic"] = process_traffic_repo
            return MagicMock()

        monkeypatch.setattr(nmw, "NetworkMonitorWidget", _stub)

        # Darf NICHT propagieren — fail-open trotz KeyManager-Defekt.
        NetworkMonitorTool().create_widget()
        assert captured["repository"] is None
        assert captured["traffic"] is None
