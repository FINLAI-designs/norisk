"""network_monitor.data.etw_event_normalizer — ETW-Wire-Format → Aggregator-Payload.

Anti-Corruption-Adapter zwischen dem rohen ``Microsoft-Windows-Kernel-Network``-
Event (wie pywintrace es liefert) und dem schlanken Payload-Dict, das
:meth:`~tools.network_monitor.application.etw_traffic_aggregator.EtwTrafficAggregator.add_event`
erwartet (``PID``, ``size``, ``daddr``/``saddr`` als IP-String).

Liegt bewusst in ``data/`` (nicht ``application/``): das Dekodieren des
ETW-Drahtformats — insbesondere der IP-Adressen — ist Adapter-Verantwortung. So
bleibt der Aggregator (``application/``) frei von Wire-Format-Wissen, und der
Subscriber (``data/``) muss nicht in die ``application/``-Schicht greifen
(Import-Linter-Contract „data darf nicht in application greifen").

WICHTIG — IP-Byte-Order (B2-Fund, Web-Recherche 2026-05-25): Der
Kernel-Network-Provider liefert ``daddr``/``saddr`` als **UInt32** (IPv4) bzw.
**16-Byte-Binary** (IPv6) — NICHT als fertigen IP-String. TDH liest die 4 Netzwerk-
Bytes [a,b,c,d] auf einer Little-Endian-Maschine als ``d<<24|c<<16|b<<8|a``;
:func:`decode_ipv4_uint32` packt daher Little-Endian zurueck. Diese Annahme ist
**am echten elevated-Event zu verifizieren** (B2-Smoke) — falls die IPs gespiegelt
erscheinen, ist auf Big-Endian-Packing umzustellen.

Schichtzugehoerigkeit: ``data/`` — pure Funktionen, headless-testbar, keine
ETW-/Admin-Abhaengigkeit (operiert nur auf dicts/ints/bytes).
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from typing import Any, Final

#: Felder, die unveraendert (roh) an den Aggregator durchgereicht werden — er
#: uebernimmt die int-Coercion selbst (siehe ``etw_traffic_aggregator``).
_PID_KEYS: Final[tuple[str, ...]] = ("PID", "pid")
_SIZE_KEYS: Final[tuple[str, ...]] = ("size", "Size")
#: Adress-Felder, die von UInt32/Binary nach IP-String dekodiert werden.
_ADDR_KEYS: Final[tuple[str, ...]] = ("daddr", "saddr")
#: Port-Felder, roh durchgereicht (Aggregator coerced nach int).
_PORT_KEYS: Final[tuple[str, ...]] = ("dport", "sport")


def decode_ipv4_uint32(value: int) -> str:
    """Dekodiert eine als UInt32 gelieferte IPv4-Adresse zum Dotted-String.

    Annahme (B2-Smoke verifizieren): Little-Endian-Packing — die 4 Netzwerk-
    Bytes wurden als nativer UInt32 auf x86 gelesen.

    Args:
        value: IPv4-Adresse als 32-Bit-Ganzzahl.

    Returns:
        Dotted-Decimal-String (z.B. ``"1.2.3.4"``), oder ``""`` bei
        ungueltigem Wertebereich.
    """
    if not 0 <= value <= 0xFFFFFFFF:
        return ""
    return socket.inet_ntoa(struct.pack("<I", value))


def decode_ipv6_bytes(raw: bytes) -> str:
    """Dekodiert eine als 16-Byte-Binary gelieferte IPv6-Adresse.

    Args:
        raw: 16 rohe Bytes der IPv6-Adresse (Network-Byte-Order).

    Returns:
        Komprimierter IPv6-String (z.B. ``"2607:f8b0::1"``), oder ``""`` bei
        falscher Laenge.
    """
    if len(raw) != 16:
        return ""
    return socket.inet_ntop(socket.AF_INET6, raw)


def decode_address(value: Any) -> str:
    """Robuste Adress-Dekodierung unabhaengig vom gelieferten Roh-Typ.

    Behandelt alle Formen, in denen pywintrace ``daddr``/``saddr`` liefern kann:
    bereits fertiger IP-String (Pass-through), UInt32 (IPv4), 4-Byte- oder
    16-Byte-Binary (IPv4/IPv6). Unbekanntes/leeres ergibt ``""`` — der
    Aggregator behandelt leere Hosts ohnehin tolerant.

    Args:
        value: Roh-Adresswert aus dem ETW-Event.

    Returns:
        IP-String oder ``""`` wenn nicht dekodierbar.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        # Schon ein String — als IP validieren, sonst (z.B. reiner Zahl-String)
        # als UInt32 interpretieren.
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            try:
                return decode_ipv4_uint32(int(value))
            except (ValueError, TypeError):
                return ""
    if isinstance(value, bool):
        return ""  # bool ist int-Subklasse — explizit ausschliessen
    if isinstance(value, int):
        return decode_ipv4_uint32(value)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) == 4:
            return socket.inet_ntoa(raw)
        if len(raw) == 16:
            return decode_ipv6_bytes(raw)
        return ""
    return ""


def normalize_kernel_network_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Uebersetzt ein rohes Kernel-Network-Event in den Aggregator-Payload.

    Reicht ``PID``/``size`` roh durch (der Aggregator coerced selbst) und
    dekodiert die Adress-Felder zu IP-Strings. Fehlende Felder werden
    ausgelassen — der Aggregator ignoriert Events ohne ``PID``/``size``.

    Args:
        payload: Rohes Event-Dict aus dem pywintrace-Callback (Property-Keys
            wie ``PID``, ``size``, ``daddr``, ``saddr`` …).

    Returns:
        Schlankes Dict mit ``PID``, ``size`` und dekodierten ``daddr``/``saddr``.
    """
    out: dict[str, Any] = {}
    for key in _PID_KEYS:
        if key in payload:
            out["PID"] = payload[key]
            break
    for key in _SIZE_KEYS:
        if key in payload:
            out["size"] = payload[key]
            break
    for key in _ADDR_KEYS:
        if key in payload:
            decoded = decode_address(payload[key])
            if decoded:
                out[key] = decoded
    for key in _PORT_KEYS:
        if key in payload:
            out[key] = payload[key]
    return out
