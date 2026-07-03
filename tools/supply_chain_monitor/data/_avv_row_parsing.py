"""
_avv_row_parsing — geteilte Row-Parser fuer die AVV-Repositories.

Lieferanten-AVVs (:mod:`avv_repository`) und Kunden-AVVs
(:mod:`customer_avv_repository`) teilen die Datum-/Status-Parsing-Logik beim
Row-Mapping. Gemeinsames Modul gegen Copy-Paste-Drift (Review-Befund).

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.logger import get_logger
from tools.supply_chain_monitor.domain.models import AvvDocumentStatus

_log = get_logger(__name__)


def safe_status(value: str) -> AvvDocumentStatus:
    """Mappt einen DB-Statuswert auf das Enum; fail-soft Fallback auf ACTIVE.

    Args:
        value: Persistierter Status-String.

    Returns:
        Das passende:class:`AvvDocumentStatus`; bei unbekanntem Wert ``ACTIVE``
        (mit Warn-Log zur Diagnose).
    """
    try:
        return AvvDocumentStatus(value)
    except ValueError:
        _log.warning("Unbekannter AVV-Status '%s' -> Fallback ACTIVE.", value)
        return AvvDocumentStatus.ACTIVE


def parse_iso_utc(value: str | None) -> datetime:
    """Parst einen ISO-8601-Timestamp; fail-soft Fallback auf ``datetime.now(UTC)``.

    Args:
        value: ISO-8601-String oder ``None``.

    Returns:
        Das geparste Datum oder die aktuelle UTC-Zeit bei leerem/ungueltigem Wert.
    """
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
