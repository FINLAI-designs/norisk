"""channel_router — Mapping ``Urgency`` → ``Channel`` (Sprint S1a).

Eine kleine, deterministische Routing-Tabelle. Bewusst getrennt vom
Builder, damit Konsumenten den Kanal eigenständig vom Urgency ableiten
können (z. B. ein Wochenreport, der nur ``Story.channel ==
WOCHEN_REPORT`` selektiert, ohne den vollen Builder zu durchlaufen).

Routing-Regeln (aus der Information-Value-Strategie, Sektion 2):

- ``AKUT`` → ``NOTIFICATION`` (Push raus, jetzt)
- ``WICHTIG`` → ``DASHBOARD_HERO`` (sichtbar auf der Übersicht)
- ``TREND`` → ``AKKORDEON_DETAIL`` (zugeklappt, manuell aufklappbar)
- ``KONTEXT`` → ``WOCHEN_REPORT`` (nur im PDF-Wochenbericht)

Schichtzugehörigkeit: core/ — kein PySide6, keine DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.storytelling.schemas import Channel, Urgency

# ---------------------------------------------------------------------------
# Routing-Tabelle
# ---------------------------------------------------------------------------

_ROUTING: dict[Urgency, Channel] = {
    Urgency.AKUT: Channel.NOTIFICATION,
    Urgency.WICHTIG: Channel.DASHBOARD_HERO,
    Urgency.TREND: Channel.AKKORDEON_DETAIL,
    Urgency.KONTEXT: Channel.WOCHEN_REPORT,
}


def route(urgency: Urgency) -> Channel:
    """Ordnet eine Urgency dem zugehörigen Anzeige-Kanal zu.

    Total — jede ``Urgency`` hat genau einen ``Channel`` (:data:`_ROUTING`). Wird vom:func:`narrative_builder.build_story`
    aufgerufen, kann aber auch isoliert genutzt werden (z. B. UI-Filter
    "nur Notification-Stories anzeigen").

    Args:
        urgency: Die Urgency-Klassifikation eines Findings.

    Returns:
        Der zugehörige Anzeige-Kanal.

    Raises:
        KeyError: Wenn ``urgency`` nicht in der Routing-Tabelle ist —
            sollte bei korrekt typisiertem Eingang nie passieren, ist
            aber durch:class:`Urgency` als ``StrEnum`` strukturell
            verhindert.
    """
    return _ROUTING[urgency]
