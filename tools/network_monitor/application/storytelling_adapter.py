"""storytelling_adapter — network_monitor Anomalien → FindingInput E).

Konvertiert:class:`~tools.network_monitor.domain.models.Anomaly` in
:class:`~core.storytelling.schemas.FindingInput` und speist sie (optional) ueber
den:class:`~core.storytelling.ki_todo_emitter.KiTodoEmitter` in die KI-Todo-
Engine (Welcome-Page-„Was tun?"-Section). Muster analog
``tools/patch_monitor/application/storytelling_adapter.py``.

Anomaly-Typ → finding_type (Template-Lookup-Key zusammen mit ``tool``):

================= ====================== ==========
AnomalyType finding_type severity
================= ====================== ==========
volume_spike volume_anomaly HIGH
off_hours off_hours MEDIUM
single_ip single_ip_exfil HIGH
game_cdn game_download LOW
unknown_path unknown_process HIGH
dns_tunneling dns_tunneling (Phase 2b)
================= ====================== ==========

Die zugehoerigen Storytelling-Templates (``network_monitor/volume_anomaly`` etc.)
sind ein eigener Folge-Substep — ohne sie erzeugt ``emit`` keine Tasks (no-op).

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein direktes ``data/``).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from core.logger import get_logger
from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity
from tools.network_monitor.domain.models import (
    Anomaly,
    AnomalySeverity,
    AnomalyType,
)

log = get_logger(__name__)

#: Tool-Bezeichner (Template-/Registry-Match).
TOOL_NAME: Final[str] = "network_monitor"

_FINDING_TYPE: Final[dict[AnomalyType, str]] = {
    AnomalyType.VOLUME_SPIKE: "volume_anomaly",
    AnomalyType.OFF_HOURS: "off_hours",
    AnomalyType.SINGLE_IP: "single_ip_exfil",
    AnomalyType.GAME_CDN: "game_download",
    AnomalyType.UNKNOWN_PATH: "unknown_process",
    AnomalyType.DNS_TUNNELING: "dns_tunneling",
}

_SEVERITY_MAP: Final[dict[AnomalySeverity, Severity]] = {
    AnomalySeverity.HIGH: Severity.HIGH,
    AnomalySeverity.MEDIUM: Severity.MEDIUM,
    AnomalySeverity.LOW: Severity.LOW,
}


def _evidence_id(anomaly: Anomaly) -> str:
    """Stabile Dedup-ID: Typ + Prozess (+ Remote-IP, falls vorhanden)."""
    parts = [anomaly.anomaly_type.value, anomaly.process_name or str(anomaly.pid)]
    if anomaly.remote_ip:
        parts.append(anomaly.remote_ip)
    return ":".join(parts)


def anomalies_to_findings(anomalies: Iterable[Anomaly]) -> list[FindingInput]:
    """Konvertiert Anomalien zu:class:`FindingInput` (Reihenfolge bleibt).

    Anomalien mit unbekanntem Typ werden uebersprungen; Konvertierungsfehler
    werden geloggt und ausgelassen (Adapter darf nie crashen).
    """
    findings: list[FindingInput] = []
    for anomaly in anomalies:
        finding_type = _FINDING_TYPE.get(anomaly.anomaly_type)
        if finding_type is None:
            continue
        severity = _SEVERITY_MAP.get(anomaly.severity, Severity.MEDIUM)
        details = {
            "anomaly_type": anomaly.anomaly_type.value,
            "pid": anomaly.pid,
            "process_name": anomaly.process_name,
            "value_bytes": anomaly.value_bytes,
            "threshold_bytes": anomaly.threshold_bytes,
            "remote_ip": anomaly.remote_ip,
            "detail": anomaly.detail,
        }
        try:
            findings.append(
                FindingInput(
                    tool=TOOL_NAME,
                    finding_type=finding_type,
                    severity=severity,
                    subject=anomaly.process_name or f"PID {anomaly.pid}",
                    evidence_id=_evidence_id(anomaly),
                    details=details,
                )
            )
        except Exception as exc:  # noqa: BLE001 — Adapter darf nie crashen
            log.warning(
                "anomaly-adapter: %s nicht konvertierbar (%s)",
                anomaly.anomaly_type,
                type(exc).__name__,
            )
    return findings


def emit_anomalies(anomalies: Iterable[Anomaly], emitter: object | None = None) -> int:
    """Baut Findings und reicht sie an den KiTodoEmitter (no-op ohne Service).

    Args:
        anomalies: Erkannte Anomalien.
        emitter: Optionaler Emitter (Tests). Default: lazy
:class:`KiTodoEmitter` (vermeidet harte Kopplung beim Import).

    Returns:
        Anzahl erzeugter Findings (auch wenn der Emitter sie verwirft).
    """
    findings = anomalies_to_findings(anomalies)
    if not findings:
        return 0
    if emitter is None:
        from core.storytelling.ki_todo_emitter import KiTodoEmitter

        emitter = KiTodoEmitter()
    emitter.emit(findings)  # type: ignore[attr-defined]
    return len(findings)


__all__ = ["TOOL_NAME", "anomalies_to_findings", "emit_anomalies"]
