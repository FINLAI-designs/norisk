"""network_monitor.data.dns_event_normalizer — DNS-Client-ETW → Aggregator-Payload Regel 5).

Anti-Corruption-Adapter fuer den Provider ``Microsoft-Windows-DNS-Client``
(Event 3006 „DNS query is called"). Anders als beim Kernel-Network-Provider
steht die **PID nicht im Payload**, sondern im ``EventHeader.ProcessId`` — diese
Eigenheit kapselt der Normalizer hier.

Liegt in ``data/`` (Wire-Format-Uebersetzung), pure + headless-testbar.
"""

from __future__ import annotations

from typing import Any, Final

from tools.network_monitor.data.etw_sanitize import sanitize_text

_PID_HEADER_KEYS: Final[tuple[str, ...]] = ("ProcessId", "PID", "pid")
_NAME_KEYS: Final[tuple[str, ...]] = ("QueryName", "queryname", "Name")
_TYPE_KEYS: Final[tuple[str, ...]] = ("QueryType", "querytype")
#: Obergrenze fuer DNS-Query-Namen (RFC 1035: max. 255 Oktette fuer einen FQDN).
#: Lokale Prozesse koennen beliebige Namen abfragen — im elevated Collector hart
#: begrenzt, damit kein unbounded/steuerzeichen-String in DB/Log fliesst.
_MAX_QUERY_NAME_LEN: Final[int] = 255


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _extract_pid(raw: dict[str, Any]) -> int | None:
    """Liest die PID aus dem ``EventHeader`` (DNS-Client-Eigenheit)."""
    header = raw.get("EventHeader")
    if isinstance(header, dict):
        pid = _coerce_int(header.get("ProcessId"))
        if pid is not None:
            return pid
    # Fallback: manche Wrapper flachen den Header in den Payload.
    for key in _PID_HEADER_KEYS:
        if key in raw:
            pid = _coerce_int(raw[key])
            if pid is not None:
                return pid
    return None


def _first(raw: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None


def normalize_dns_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Uebersetzt ein rohes DNS-Client-Event in den Aggregator-Payload.

    Args:
        raw: Rohes Event-Dict aus dem pywintrace-Callback (``EventHeader`` +
            ``QueryName``/``QueryType`` …).

    Returns:
        ``{"pid": int, "query_name": str, "query_type": int}`` — fehlende
        Felder werden ausgelassen (der Aggregator ignoriert Events ohne PID).
    """
    out: dict[str, Any] = {}
    pid = _extract_pid(raw)
    if pid is not None:
        out["pid"] = pid
    name = _first(raw, _NAME_KEYS)
    if name is not None:
        cleaned = sanitize_text(name, max_len=_MAX_QUERY_NAME_LEN)
        if cleaned:  # nach dem Strippen leer (z. B. nur Steuerzeichen) -> weglassen
            out["query_name"] = cleaned
    qtype = _coerce_int(_first(raw, _TYPE_KEYS))
    if qtype is not None:
        out["query_type"] = qtype
    return out
