"""Tests fuer den network_monitor-Storytelling-Adapter E).

Anomaly → FindingInput-Mapping + Emit-Verdrahtung (Fake-Emitter), pure.
"""

from __future__ import annotations

from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity
from tools.network_monitor.application.storytelling_adapter import (
    TOOL_NAME,
    anomalies_to_findings,
    emit_anomalies,
)
from tools.network_monitor.domain.models import (
    Anomaly,
    AnomalySeverity,
    AnomalyType,
)


def _anomaly(
    atype: AnomalyType = AnomalyType.SINGLE_IP,
    severity: AnomalySeverity = AnomalySeverity.HIGH,
    pid: int = 10,
    name: str = "evil.exe",
    remote_ip: str = "8.8.8.8",
) -> Anomaly:
    return Anomaly(
        anomaly_type=atype,
        severity=severity,
        pid=pid,
        process_name=name,
        value_bytes=11_000_000_000,
        threshold_bytes=10_000_000_000,
        remote_ip=remote_ip,
    )


class TestAnomaliesToFindings:
    def test_mapping_typ_severity_tool(self) -> None:
        findings = anomalies_to_findings([_anomaly()])
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, FindingInput)
        assert f.tool == TOOL_NAME
        assert f.finding_type == "single_ip_exfil"
        assert f.severity == Severity.HIGH
        assert f.subject == "evil.exe"

    def test_evidence_id_enthaelt_ip(self) -> None:
        f = anomalies_to_findings([_anomaly(remote_ip="9.9.9.9")])[0]
        assert "9.9.9.9" in f.evidence_id
        assert f.evidence_id.startswith("single_ip")

    def test_off_hours_medium(self) -> None:
        f = anomalies_to_findings(
            [_anomaly(atype=AnomalyType.OFF_HOURS, severity=AnomalySeverity.MEDIUM, remote_ip="")]
        )[0]
        assert f.finding_type == "off_hours"
        assert f.severity == Severity.MEDIUM

    def test_details_enthaelt_kennzahlen(self) -> None:
        f = anomalies_to_findings([_anomaly()])[0]
        assert f.details["value_bytes"] == 11_000_000_000
        assert f.details["remote_ip"] == "8.8.8.8"

    def test_leere_liste(self) -> None:
        assert anomalies_to_findings([]) == []


class _FakeEmitter:
    def __init__(self) -> None:
        self.received: list | None = None

    def emit(self, findings) -> None:  # noqa: ANN001
        self.received = list(findings)


class TestEmitAnomalies:
    def test_emit_reicht_findings_durch(self) -> None:
        emitter = _FakeEmitter()
        count = emit_anomalies([_anomaly(), _anomaly(atype=AnomalyType.VOLUME_SPIKE)], emitter)
        assert count == 2
        assert emitter.received is not None
        assert len(emitter.received) == 2

    def test_emit_leer_ruft_emitter_nicht(self) -> None:
        emitter = _FakeEmitter()
        assert emit_anomalies([], emitter) == 0
        assert emitter.received is None
