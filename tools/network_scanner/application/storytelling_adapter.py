"""storytelling_adapter — network_scanner → FindingInput a/b).

Konvertiert offene Ports aus:class:`NetworkScanResult` in ``FindingInput``-
Objekte fuer das ``exposed_admin_port``-Storytelling-Template. Triggert
nur fuer Ports mit Risikoklasse KRITISCH oder HOCH — info-/niedrig-Risiko-
Ports erzeugen kein KI-Todo.

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein direktes data/).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from core.security.severity import Severity
from core.storytelling.schemas import FindingInput
from tools.network_scanner.domain.analyzer import HIGH_RISK_PORTS
from tools.network_scanner.domain.models import (
    NetworkScanResult,
    PortInfo,
    PortRisk,
    PortState,
)

log = get_logger(__name__)


def network_result_to_ki_inputs(
    result: NetworkScanResult,
) -> list[FindingInput]:
    """Wandelt offene Ports in:class:`FindingInput`-Objekte.

    Pro offenem Port mit ``risk in (KRITISCH, HOCH)`` wird ein Finding
    erzeugt. Andere Ports (MITTEL/NIEDRIG/INFO) werden uebersprungen —
    sie sind nicht akut genug fuer ein KI-Todo.

    Args:
        result: Ergebnis von:func:`NetworkService.starte_scan`.

    Returns:
        Liste der:class:`FindingInput`. Leer wenn keine relevanten Ports.
    """
    inputs: list[FindingInput] = []
    for host in result.hosts:
        # Pydantic FindingInput verlangt min_length=1 fuer subject.
        # Defensive: Hosts ohne `host`-Feld werden uebersprungen.
        if not host.host:
            continue
        for port_info in host.offene_ports:
            if port_info.state != PortState.OPEN:
                continue
            if port_info.risk not in (PortRisk.KRITISCH, PortRisk.HOCH):
                continue
            inputs.append(
                FindingInput(
                    tool="network_scanner",
                    finding_type="exposed_admin_port",
                    severity=_severity_for_port_risk(port_info.risk),
                    subject=host.host,
                    evidence_id=f"{host.host}#{port_info.port}",
                    details=_details_for_port(port_info),
                )
            )
    return inputs


def _severity_for_port_risk(risk: PortRisk) -> Severity:
    """``PortRisk`` (deutsche Lowercase-Werte) → kanonisches ``Severity``."""
    if risk == PortRisk.KRITISCH:
        return Severity.CRITICAL
    if risk == PortRisk.HOCH:
        return Severity.HIGH
    if risk == PortRisk.MITTEL:
        return Severity.MEDIUM
    if risk == PortRisk.NIEDRIG:
        return Severity.LOW
    return Severity.INFO


def _details_for_port(port_info: PortInfo) -> dict:
    """Baut das ``details``-Dict fuer das Storytelling-Template.

    Bevorzugt den Service-Namen aus:data:`HIGH_RISK_PORTS` (kanonisch,
    konsistent ueber alle Tools), faellt auf den vom Scanner ermittelten
    ``service``-String zurueck.
    """
    risk_entry = HIGH_RISK_PORTS.get(port_info.port)
    service_name = risk_entry[1] if risk_entry else (port_info.service or "?")
    return {
        "port": port_info.port,
        "protocol": "TCP",  # SocketScanner + Nmap-Default
        "service_name": service_name,
    }


def emit_to_ki_emitter(emitter, result: NetworkScanResult) -> list[FindingInput]:
    """Convenience: konvertiert + ruft ``emitter.emit`` auf.

    Fail-safe: Konvertierungs-Fehler werden geloggt und schlucken — Hook
    darf den Scan nicht brechen.
    """
    try:
        inputs = network_result_to_ki_inputs(result)
    except Exception as exc:  # noqa: BLE001 -- Hook darf Scan nicht brechen
        log.warning(
            "network_scanner → FindingInput-Konvertierung fehlgeschlagen: %s: %s",
            type(exc).__name__,
            str(exc)[:200],
        )
        return []
    emitter.emit(inputs)
    return inputs
