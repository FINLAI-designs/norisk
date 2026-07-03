"""Tests fuer den AnomalyDetectionWorker F-E).

Testet den extrahierten Detektions-Schritt ``_detect_once`` (ohne Thread-Loop /
``msleep``): emittiert die detect-Anomalien bzw. einen Fehler fail-soft.
"""

from __future__ import annotations

from unittest.mock import Mock

from tools.network_monitor.domain.models import Anomaly, AnomalySeverity, AnomalyType
from tools.network_monitor.gui.anomaly_worker import AnomalyDetectionWorker


def _anomaly() -> Anomaly:
    return Anomaly(
        anomaly_type=AnomalyType.VOLUME_SPIKE,
        severity=AnomalySeverity.HIGH,
        pid=1,
        process_name="chrome.exe",
        value_bytes=2_000_000,
        threshold_bytes=1_000_000,
    )


class TestDetectOnce:
    def test_emittiert_anomalien(self, qtbot) -> None:
        service = Mock()
        service.detect.return_value = [_anomaly()]
        worker = AnomalyDetectionWorker(service)
        captured: list = []
        worker.anomalies_detected.connect(captured.append)

        worker._detect_once()

        service.detect.assert_called_once()
        assert captured == [[_anomaly()]]  # frozen dataclass -> Wert-Gleichheit

    def test_fehler_wird_fail_soft_gemeldet(self, qtbot) -> None:
        service = Mock()
        service.detect.side_effect = RuntimeError("DB weg")
        worker = AnomalyDetectionWorker(service)
        errors: list[str] = []
        anomalies: list = []
        worker.error_occurred.connect(errors.append)
        worker.anomalies_detected.connect(anomalies.append)

        worker._detect_once()  # darf NICHT durchschlagen

        assert errors
        # Roh-Exception-Text leakt NICHT ins Signal (nur generische Meldung).
        assert "DB weg" not in errors[0]
        assert "nicht verfügbar" in errors[0]
        assert anomalies == []  # kein anomalies_detected-Emit bei Fehler

    def test_stop_setzt_flag(self, qtbot) -> None:
        worker = AnomalyDetectionWorker(Mock())
        assert worker._stop_flag is False
        worker.stop()
        assert worker._stop_flag is True
