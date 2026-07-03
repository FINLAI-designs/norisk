"""test_storytelling_adapter_network_scanner (a)+(b)."""

from __future__ import annotations

from datetime import UTC, datetime

from core.security.severity import Severity
from tools.network_scanner.application.storytelling_adapter import (
    network_result_to_ki_inputs,
)
from tools.network_scanner.domain.models import (
    HostInfo,
    NetworkScanResult,
    PortInfo,
    PortRisk,
    PortState,
)


def _result_with_port(
    port: int,
    risk: PortRisk = PortRisk.KRITISCH,
    state: PortState = PortState.OPEN,
    service: str = "",
) -> NetworkScanResult:
    port_info = PortInfo(port=port, state=state, risk=risk, service=service)
    host = HostInfo(host="192.168.1.1", erreichbar=True, offene_ports=[port_info])
    return NetworkScanResult(
        ziel="192.168.1.1",
        hosts=[host],
        gestartet_am=datetime.now(UTC),
        beendet_am=datetime.now(UTC),
        scanner_typ="socket",
    )


class TestPortFilter:
    def test_kritischer_port_wird_gemeldet(self) -> None:
        result = _result_with_port(3389, PortRisk.KRITISCH)
        inputs = network_result_to_ki_inputs(result)
        assert len(inputs) == 1
        assert inputs[0].finding_type == "exposed_admin_port"
        assert inputs[0].details["port"] == 3389
        assert inputs[0].details["service_name"] == "RDP"

    def test_hoher_port_wird_gemeldet(self) -> None:
        result = _result_with_port(8080, PortRisk.HOCH, service="HTTP-Alt")
        inputs = network_result_to_ki_inputs(result)
        assert len(inputs) == 1
        assert inputs[0].severity == Severity.HIGH

    def test_mittlerer_port_wird_uebersprungen(self) -> None:
        result = _result_with_port(8080, PortRisk.MITTEL)
        assert network_result_to_ki_inputs(result) == []

    def test_info_port_wird_uebersprungen(self) -> None:
        result = _result_with_port(80, PortRisk.INFO)
        assert network_result_to_ki_inputs(result) == []

    def test_geschlossener_port_wird_uebersprungen(self) -> None:
        result = _result_with_port(3389, PortRisk.KRITISCH, state=PortState.CLOSED)
        assert network_result_to_ki_inputs(result) == []


class TestSeverityMapping:
    def test_kritisch_critical(self) -> None:
        result = _result_with_port(445, PortRisk.KRITISCH)
        assert network_result_to_ki_inputs(result)[0].severity == Severity.CRITICAL

    def test_hoch_high(self) -> None:
        result = _result_with_port(8080, PortRisk.HOCH)
        assert network_result_to_ki_inputs(result)[0].severity == Severity.HIGH


class TestDetails:
    def test_service_name_aus_high_risk_ports(self) -> None:
        """Bekannter Port → Service-Name aus HIGH_RISK_PORTS-Mapping."""
        result = _result_with_port(445, PortRisk.KRITISCH, service="ignored-from-scanner")
        inputs = network_result_to_ki_inputs(result)
        assert inputs[0].details["service_name"] == "SMB"  # aus HIGH_RISK_PORTS

    def test_service_name_fallback_auf_scanner_string(self) -> None:
        """Unbekannter Port → Scanner-Service-String."""
        result = _result_with_port(31337, PortRisk.HOCH, service="elite")
        inputs = network_result_to_ki_inputs(result)
        assert inputs[0].details["service_name"] == "elite"

    def test_evidence_id_enthaelt_port(self) -> None:
        result = _result_with_port(3389, PortRisk.KRITISCH)
        assert "#3389" in network_result_to_ki_inputs(result)[0].evidence_id

    def test_subject_ist_host(self) -> None:
        result = _result_with_port(3389, PortRisk.KRITISCH)
        assert network_result_to_ki_inputs(result)[0].subject == "192.168.1.1"
