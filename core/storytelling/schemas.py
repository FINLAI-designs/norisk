"""schemas — Pydantic-Modelle für die Storytelling-Engine (Sprint S1a).

Definiert die drei Schlüsseltypen:

-:class:`Urgency` — wie dringlich ist dieser Befund?
-:class:`Channel` — wo wird er angezeigt? (von:mod:`channel_router` befüllt)
-:class:`FindingInput` — normalisierter Eingang für die Engine
-:class:`Story` — gerenderte Ausgabe für Konsumenten

Schichtzugehörigkeit: core/ — kein PySide6, kein DB-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.vulnerability.domain.severity import Severity

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Urgency(StrEnum):
    """Dringlichkeits-Klassifikation eines Findings.

    Vier Stufen — bewusst weniger granular als ``Severity``, weil die
    Dringlichkeit Kontext mit einbezieht (z. B. ist eine ``HIGH``-Severity
    auf einem internen Server weniger akut als auf einem öffentlichen).

    Reihenfolge (absteigend in Dringlichkeit):
      AKUT > WICHTIG > TREND > KONTEXT.
    """

    AKUT = "akut"
    WICHTIG = "wichtig"
    TREND = "trend"
    KONTEXT = "kontext"


class Channel(StrEnum):
    """Anzeige-Kanal einer Story.

    Wird vom:func:`channel_router.route` aus der Urgency abgeleitet.
    Konsumenten lesen ``Channel`` und entscheiden, ob sie die Story
    aktiv pushen (Notification), prominent zeigen (Hero) oder im Detail
    ausklappen.

    **Patrick-Entscheidung 2026-04-29 (Sprint S1a-Review):** ``NOTIFICATION``
    bedeutet **nur In-App**-Notification — keine OS-/Push-Notification.
    Konsumenten sollen die Story als In-App-Toast/Banner anzeigen, nicht
    über das System-Benachrichtigungs-Center.
    """

    NOTIFICATION = "notification"          # In-App-Toast / Banner, sofort sichtbar
    DASHBOARD_HERO = "dashboard_hero"      # Hero-Karte auf der Übersicht
    AKKORDEON_DETAIL = "akkordeon_detail"  # zugeklappt, manuell aufklappbar
    WOCHEN_REPORT = "wochen_report"        # nur im wöchentlichen PDF-Bericht


# ---------------------------------------------------------------------------
# Eingangs-Modell
# ---------------------------------------------------------------------------


class FindingInput(BaseModel):
    """Normalisierter Eingang für die Storytelling-Engine.

    Tools melden ihre Findings nicht direkt in tool-spezifischer Form
    an die Engine, sondern bauen vorher dieses Pydantic-Modell —
    so bleiben die Templates entkoppelt von Tool-Domänen.

    Attributes:
        tool: Tool-Bezeichner (passend zu:data:`core.registry.last_scan_registry`),
            z. B. ``"cert_monitor"`` / ``"api_security"`` / ``"network_scanner"`` /
            ``"csaf_advisor"`` / ``"dependency_auditor"``.
        finding_type: Tool-spezifischer Typ-Schlüssel (z. B.
            ``"cert_expiring"``). Zusammen mit ``tool`` der Lookup-Key
            für die Template-Registry.
        severity: Kanonische Severity (S0a). Templates lesen diese, um
            Urgency abzuleiten.
        subject: Worum geht es? Beispiele: ``"owncloud.example.com"``,
            ``"requests==2.30"``, ``"Port 3389/RDP"``.
        evidence_id: Stabile Referenz auf das Finding im Quell-Tool
            (DB-Primary-Key oder fachlicher Schlüssel). Wird 1:1 als
            ``Story.evidence_finding_id`` durchgereicht — Konsumenten
            können damit zurück zum Detail-View navigieren.
        details: Template-spezifische Zusatzfelder. Welche Keys hier
            erwartet werden, dokumentiert das jeweilige Template in
:mod:`finding_templates`. Standard: leerer Dict.
    """

    tool: str = Field(min_length=1)
    finding_type: str = Field(min_length=1)
    severity: Severity
    subject: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True)


# ---------------------------------------------------------------------------
# Ausgangs-Modell
# ---------------------------------------------------------------------------


class Story(BaseModel):
    """Gerenderte Story — vom:func:`narrative_builder.build_story` produziert.

    Die Felder folgen der Information-Value-Vision (Schicht 2 der Strategie):
    *Headline* hookt, *Explanation* bedeutet, *Action* sagt was tun.

    Attributes:
        urgency: Dringlichkeits-Klassifikation. Wird vom Template aus
            ``FindingInput.severity`` und kontextspezifischen Feldern
            in ``details`` abgeleitet.
        headline: Eine Zeile, ≤ 90 Zeichen empfohlen. Verb voran wenn
            möglich — der User soll auf einen Blick die Bedrohung erfassen.
        explanation: 1–3 Sätze. Erklärt was, warum, wie schlimm — in
            KMU-tauglicher Sprache, ohne Buzzwords.
        action: Was tun? 1–2 Sätze. Konkret, handlungsorientiert, wenn
            möglich mit Zeitabschätzung ("ca. 5 Min").
        evidence_finding_id: Durchgereicht aus:class:`FindingInput`
            für Drill-Down zum Quell-Tool.
        channel: Anzeige-Kanal — vom:func:`channel_router.route`
            anhand der Urgency gesetzt.
    """

    urgency: Urgency
    headline: str = Field(min_length=1, max_length=200)
    explanation: str = Field(min_length=1)
    action: str = Field(min_length=1)
    evidence_finding_id: str = Field(min_length=1)
    channel: Channel

    model_config = ConfigDict(frozen=True)
