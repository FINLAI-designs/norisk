"""core/storytelling — Daten → Geschichte (Sprint S1a).

Schicht 2 der Information-Value-Strategie. Wandelt rohe Findings (aus
api_security, cert_monitor, network_scanner, csaf_advisor,
dependency_auditor) in eine **kuratierte Story** um — mit Headline,
Erklärung, klarer Aktion und einer Dringlichkeits-Klassifikation.

Konsumenten:
  - Erklär-Layer (Schicht 3, Sprint S1c): Tooltips
  - KI-Todos / Regel-Engine (Schicht 4, Sprint S2a/S2b): Karten-Texte
  - Dashboard-Hero (Schicht 5, Sprint S4b): Hero-Story
  - Wochen-Report-PDF (S4b+): Kontext-Sektion

Public API:
  -:class:`schemas.Story` — gerenderte Story
  -:class:`schemas.FindingInput` — normalisierter Eingang
  -:class:`schemas.Urgency` — AKUT / WICHTIG / TREND / KONTEXT
  -:class:`schemas.Channel` — Anzeige-Kanal
  -:func:`narrative_builder.build_story`
  -:func:`channel_router.route`

Schichtzugehörigkeit: core/ — framework-agnostisch (kein PySide6, keine
DB). Templates sind reine Funktionen mit Pydantic-Schemas.
"""
