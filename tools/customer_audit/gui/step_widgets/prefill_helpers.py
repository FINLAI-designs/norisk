"""prefill_helpers — Gemeinsame Helfer fuer die SELF-Vorbefuellung Phase 3).

EINE Quelle fuer die kleinen, von Infrastructure- UND Network-Step geteilten
Funktionen rund um den gemessenen:class:`AuditPrefill` (Datums-Format,
Herkunfts-Tooltip, OS-Options-Match) — kein pro-Step dupliziertes Inline-Snippet
(Regel 2).

Schichtzugehoerigkeit: gui/ — reine UI-Hilfslogik, keine I/O.

Author: Patrick Riederich
Version: 1.0 Phase 3, 2026-06-27)
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from tools.customer_audit.domain.entities import BETRIEBSSYSTEME_OPTIONEN

if TYPE_CHECKING:
    from core.scan_prefill.models import MeasuredField


def fmt_iso_date(iso: str) -> str:
    """Formatiert einen ISO-8601-Zeitstempel als ``DD.MM.YYYY`` (fail-soft).

    Args:
        iso: ISO-8601-String (z. B. ``"2026-06-27T10:00:00+00:00"``).

    Returns:
        ``DD.MM.YYYY`` oder die ersten 10 Zeichen bzw. ``"?"`` als Fallback.
    """
    try:
        return datetime.fromisoformat(iso).strftime("%d.%m.%Y")
    except (ValueError, TypeError):
        return iso[:10] if iso else "?"


def origin_tooltip(field: MeasuredField) -> str:
    """Baut den Herkunfts-Tooltip ``gemessen via <check_id> (<tool>) — <detail>``.

    Args:
        field: Das gemessene:class:`MeasuredField`.

    Returns:
        Menschenlesbarer Tooltip-Text.
    """
    base = f"gemessen via {field.check_id} ({field.source_tool})"
    return f"{base} — {field.detail}" if field.detail else base


def match_os_option(os_name: str) -> str | None:
    """Mappt einen gemessenen OS-Namen auf eine ``BETRIEBSSYSTEME_OPTIONEN``-Option.

    Beispiel: ``"Windows 11"`` → ``"Windows 11"``, ``"macOS 14.2"`` → ``"macOS"``.

    Args:
        os_name: Gemessener OS-Name (z. B. aus ``OSInfo.name``).

    Returns:
        Die passende Katalog-Option oder ``None``, wenn keine matcht.
    """
    low = os_name.lower()
    for option in BETRIEBSSYSTEME_OPTIONEN:
        if option.lower() in low:
            return option
    return None
