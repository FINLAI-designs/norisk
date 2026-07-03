"""models — Pydantic-Modelle für die Regel-Engine (Sprint S2a).

Eine ``Rule`` definiert deklarativ:
  1. **Match-Kriterium** — auf welche Findings die Regel anspringt.
  2. **Klassifikator-Hinweise** — Felder, die die Heuristiken H1–H12
     in:mod:`core.rules.classifier` füttern (z. B. ``action_keywords``
     oder ``asset_count``).

Das gerenderte Match-Ergebnis ``RuleAction`` wird vom KI-Todo-Service
konsumiert und zusammen mit der Storytelling-Engine zu einer ``Task``
verdichtet.

Schichtzugehörigkeit: core/ — kein PySide6, keine DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from core.vulnerability.domain.severity import Severity


class RuleMatch(BaseModel):
    """Eingehende Match-Kriterien einer Regel.

    Eine Regel triggert, wenn **alle** Kriterien erfüllt sind:
      - ``tool`` muss exakt zum ``FindingInput.tool`` passen.
      - ``finding_type`` muss exakt zum ``FindingInput.finding_type`` passen.
      - ``min_severity`` ist die untere Schranke (inklusive). Default
        ``LOW`` — auch INFO-Befunde laufen rein, wenn der Aufrufer das
        will, und können trotzdem unten ausgefiltert werden.

    Attributes:
        tool: Tool-Bezeichner (z. B. ``"cert_monitor"``).
        finding_type: Tool-spezifischer Typ (z. B. ``"cert_expiring"``).
        min_severity: Untere Severity-Schranke (default ``LOW``).
    """

    tool: str = Field(min_length=1)
    finding_type: str = Field(min_length=1)
    min_severity: Severity = Severity.LOW

    model_config = ConfigDict(frozen=True)


class ClassifierHint(BaseModel):
    """Regel-spezifische Hinweise für den Klassifikator.

    Die Heuristiken in:mod:`core.rules.classifier` lesen primär aus dem
    Story-``action``-Text — ``ClassifierHint`` ergänzt das um Werte, die
    aus dem Text nicht ableitbar sind (z. B. wie viele Assets eine
    Aktion typischerweise betrifft).

    Attributes:
        asset_count: Geschätzte Anzahl betroffener Assets (für H2/H6/H12).
            Default ``1`` — Single-Asset-Befunde sind die häufigste Form.
        action_keywords: Optional zusätzliche Schlagwörter, die die Regel
            der Story-Action virtuell hinzufügt. Nützlich, wenn der
            Klassifikator-Heuristiken-Lauf sonst nichts greift (z. B. bei
            sehr knappen Aktions-Texten).
    """

    asset_count: int = Field(default=1, ge=1)
    action_keywords: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)


class Rule(BaseModel):
    """Eine deklarative Regel der Engine.

    Attributes:
        id: Stabiler ID-Schlüssel (z. B. ``"cert_expiring"``). Wird beim
            Laden aus YAML auf Eindeutigkeit geprüft.
        description: Kurze Beschreibung — fließt nicht in die UI, hilft
            aber beim Lesen der YAML-Datei.
        match: Match-Kriterium (:class:`RuleMatch`).
        classifier_hint: Hinweise für den Effort-Klassifikator (:class:`ClassifierHint`).
    """

    id: str = Field(min_length=1)
    description: str = ""
    match: RuleMatch
    classifier_hint: ClassifierHint = Field(default_factory=ClassifierHint)

    model_config = ConfigDict(frozen=True)


class RuleAction(BaseModel):
    """Gerendertes Match-Ergebnis — das, was der:class:`RuleEngine` liefert.

    Wird vom KI-Todo-Service zusammen mit der Storytelling-Engine zu
    einer ``Task`` verdichtet.

    Attributes:
        rule_id: ID der getriggerten Regel.
        urgency: Effort-Klasse (``quick``/``mittel``/``langfrist``)
            aus dem Klassifikator.
        finding_tool: ``FindingInput.tool`` (durchgereicht für Dedup-Key).
        finding_type: ``FindingInput.finding_type`` (durchgereicht).
        evidence_id: ``FindingInput.evidence_id`` (durchgereicht).
        severity: ``FindingInput.severity`` (durchgereicht — nützlich
            für UI-Sortierung "kritisch zuerst").
    """

    rule_id: str = Field(min_length=1)
    urgency: str = Field(min_length=1)
    finding_tool: str = Field(min_length=1)
    finding_type: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    severity: Severity

    model_config = ConfigDict(frozen=True)
