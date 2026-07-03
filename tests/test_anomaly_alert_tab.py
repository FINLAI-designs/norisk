"""Tests fuer AnomalyAlertTab F-E) — durchsuchbare Detail-Tabelle.

kein Free/Pro-Gating mehr — die Tabelle ist immer aktiv.
"""

from __future__ import annotations

from PySide6.QtCore import Qt

from tools.network_monitor.domain.models import Anomaly, AnomalySeverity, AnomalyType
from tools.network_monitor.gui.anomaly_alert_tab import AnomalyAlertTab


def _a(
    type_: AnomalyType,
    sev: AnomalySeverity,
    name: str = "proc",
    ip: str = "",
) -> Anomaly:
    return Anomaly(
        anomaly_type=type_,
        severity=sev,
        pid=1,
        process_name=name,
        value_bytes=2_000_000,
        threshold_bytes=1_000_000,
        remote_ip=ip,
    )


class TestAnomalyTab:
    def test_update_fuellt_tabelle_und_zaehler(self, qtbot) -> None:
        tab = AnomalyAlertTab()
        qtbot.addWidget(tab)
        tab.update_anomalies(
            [
                _a(AnomalyType.VOLUME_SPIKE, AnomalySeverity.HIGH),
                _a(AnomalyType.SINGLE_IP, AnomalySeverity.MEDIUM, ip="1.2.3.4"),
            ]
        )
        assert tab.anomaly_count == 2
        assert tab._table.rowCount() == 2

    def test_suche_filtert_zeilen(self, qtbot) -> None:
        tab = AnomalyAlertTab()
        qtbot.addWidget(tab)
        tab.update_anomalies(
            [
                _a(AnomalyType.VOLUME_SPIKE, AnomalySeverity.HIGH, name="chrome"),
                _a(AnomalyType.SINGLE_IP, AnomalySeverity.LOW, name="svchost"),
            ]
        )
        tab._search.setText("chrome")
        assert tab._table.rowCount() == 1
        # Gesamtzahl bleibt unveraendert (nur die Anzeige ist gefiltert).
        assert tab.anomaly_count == 2

    def test_deep_link_ip_in_zielspalte_hinterlegt(self, qtbot) -> None:
        tab = AnomalyAlertTab()
        qtbot.addWidget(tab)
        tab.update_anomalies([_a(AnomalyType.SINGLE_IP, AnomalySeverity.HIGH, ip="9.9.9.9")])
        item = tab._table.item(0, 4)
        assert item is not None
        assert item.data(Qt.ItemDataRole.UserRole) == "9.9.9.9"

    def test_leerer_zustand_zeigt_hinweis(self, qtbot) -> None:
        tab = AnomalyAlertTab()
        qtbot.addWidget(tab)
        tab.update_anomalies([])
        assert tab.anomaly_count == 0
        assert tab._table.rowCount() == 0
        assert tab._status.text()  # nicht-leerer Leer-/Voraussetzungs-Hinweis
