"""rule_engine — YAML-basierte Regel-Engine (Sprint S2a).

Lädt Regeln aus YAML-Dateien (typischerweise unter ``configs/rules/``),
hält sie in einem unveränderbaren Lookup und matcht sie gegen
:class:`core.storytelling.schemas.FindingInput`-Eingänge::

    engine = RuleEngine.from_directory(Path("configs/rules"))
    actions = engine.evaluate(finding)
    # → list[RuleAction]; mehrere Regeln können auf dasselbe Finding
    # matchen, jede ergibt eine eigene Aktion

Eine Regel triggert, wenn:
  1. ``rule.match.tool == finding.tool`` und
  2. ``rule.match.finding_type == finding.finding_type`` und
  3. ``finding.severity >= rule.match.min_severity``.

Das Klassifikator-Ergebnis (``quick``/``mittel``/``langfrist``) wird
beim Match-Zeitpunkt direkt in die:class:`RuleAction` aufgenommen —
Konsumenten brauchen den Klassifikator nicht separat aufzurufen.

Schichtzugehörigkeit: core/ — kein PySide6, keine DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

import yaml
from pydantic import ValidationError

from core.logger import get_logger
from core.rules.classifier import classify
from core.rules.models import Rule, RuleAction
from core.storytelling.schemas import FindingInput

log = get_logger(__name__)


class RuleLoadError(ValueError):
    """Erhoben wenn die YAML-Eingabe nicht in eine valide ``Rule`` geparst werden kann.

    Wird vom Lader gefangen + protokolliert; einzelne kaputte Dateien
    blocken die Engine nicht (:meth:`RuleEngine.from_directory`).
    """


class RuleEngine:
    """Hält geladene Regeln und liefert Match-Ergebnisse.

    Die Engine ist selbst unveränderbar — nach:meth:`from_directory`
    bzw. ``__init__`` werden keine Regeln mehr verändert. Dadurch ist
    sie thread-safe für Lese-Zugriffe.

    Attributes:
        _rules_by_tool: Index ``tool -> [Rule]`` für schnelle Evaluation.
            Pro ``finding.tool`` werden nur die zugehörigen Regeln geprüft.
    """

    def __init__(self, rules: Iterable[Rule]) -> None:
        """Initialisiert die Engine mit einer Regel-Liste.

        Args:
            rules: Iterable von:class:`Rule` — typischerweise aus
:meth:`from_directory`. Doppelte ``rule.id`` sind erlaubt
                aber führen zu einer Warnung im Log.
        """
        index: dict[str, list[Rule]] = defaultdict(list)
        seen_ids: set[str] = set()
        for rule in rules:
            if rule.id in seen_ids:
                log.warning(
                    "RuleEngine: doppelte rule.id '%s' — Eintrag wird "
                    "trotzdem aktiviert, aber Konflikte sind moeglich.",
                    rule.id,
                )
            seen_ids.add(rule.id)
            index[rule.match.tool].append(rule)
        self._rules_by_tool: dict[str, list[Rule]] = dict(index)

    @classmethod
    def from_directory(cls, directory: Path) -> RuleEngine:
        """Lädt alle ``*.yaml``-Dateien aus einem Verzeichnis rekursiv.

        Jede YAML-Datei darf einen Top-Level-Mapping ``rules: [...]`` oder
        eine reine Liste von Regeln enthalten — beides wird akzeptiert.
        Kaputte Dateien werden geloggt und übersprungen, damit ein einzelner
        YAML-Tippfehler nicht die ganze Engine blockiert.

        Args:
            directory: Pfad zum Regel-Verzeichnis (typisch
                ``configs/rules/``). Muss existieren — sonst leere Engine.

        Returns:
            Befüllte:class:`RuleEngine`. Bei nicht existierendem
            Verzeichnis: Engine ohne Regeln.
        """
        rules: list[Rule] = []
        if not directory.is_dir():
            log.warning(
                "RuleEngine: Verzeichnis '%s' existiert nicht — "
                "Engine bleibt leer.",
                directory,
            )
            return cls(rules)

        for yaml_path in sorted(directory.rglob("*.yaml")):
            try:
                rules.extend(_load_rules_from_yaml(yaml_path))
            except (RuleLoadError, OSError) as exc:
                log.warning(
                    "RuleEngine: '%s' uebersprungen (%s)",
                    yaml_path,
                    type(exc).__name__,
                )
                continue
        log.info(
            "RuleEngine geladen: %d Regeln aus %s",
            len(rules),
            directory,
        )
        return cls(rules)

    def rule_count(self) -> int:
        """Gesamtzahl geladener Regeln (für Telemetrie + Tests)."""
        return sum(len(rules) for rules in self._rules_by_tool.values())

    def evaluate(self, finding: FindingInput) -> list[RuleAction]:
        """Liefert die Regel-Treffer eines Findings.

        Mehrere Regeln können auf dasselbe Finding matchen — der KI-Todo-
        Service entscheidet anschließend, ob er aus mehreren Treffern
        eine kombinierte oder mehrere getrennte Tasks erzeugt.

        Args:
            finding: Normalisierter Eingang (siehe Storytelling-Engine).

        Returns:
            Liste von:class:`RuleAction` — leer wenn keine Regel matcht.
        """
        candidates = self._rules_by_tool.get(finding.tool, [])
        if not candidates:
            return []

        actions: list[RuleAction] = []
        for rule in candidates:
            if not _rule_matches_finding(rule, finding):
                continue
            urgency = classify(
                _action_seed_for_finding(finding),
                hint=rule.classifier_hint,
            )
            actions.append(
                RuleAction(
                    rule_id=rule.id,
                    urgency=urgency,
                    finding_tool=finding.tool,
                    finding_type=finding.finding_type,
                    evidence_id=finding.evidence_id,
                    severity=finding.severity,
                )
            )
        return actions


# ---------------------------------------------------------------------------
# YAML-Lader
# ---------------------------------------------------------------------------


def _load_rules_from_yaml(path: Path) -> list[Rule]:
    """Lädt eine einzelne YAML-Datei und parsed sie zu:class:`Rule`-Objekten.

    Akzeptierte Top-Level-Formate:
      - Liste: ``[{...rule1...}, {...rule2...}]``
      - Mapping mit ``rules``-Schlüssel: ``rules: [{...}, {...}]``

    Raises:
        RuleLoadError: Bei kaputtem YAML oder Schema-Fehlern in einer Regel.
    """
    raw_text = path.read_text(encoding="utf-8")
    try:
        raw_data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"YAML-Parse-Fehler in {path}: {exc}") from exc

    if isinstance(raw_data, dict):
        raw_data = raw_data.get("rules", [])
    if not isinstance(raw_data, list):
        raise RuleLoadError(
            f"{path}: erwartet Liste oder dict mit 'rules'-Key, "
            f"bekam {type(raw_data).__name__}."
        )

    parsed: list[Rule] = []
    for index, entry in enumerate(raw_data):
        try:
            parsed.append(Rule.model_validate(entry))
        except ValidationError as exc:
            raise RuleLoadError(
                f"{path} Eintrag #{index}: {exc}"
            ) from exc
    return parsed


# ---------------------------------------------------------------------------
# Match-Helper
# ---------------------------------------------------------------------------


def _rule_matches_finding(rule: Rule, finding: FindingInput) -> bool:
    """Prüft ob die Regel auf das Finding passt (alle Kriterien)."""
    if rule.match.tool != finding.tool:
        return False
    if rule.match.finding_type != finding.finding_type:
        return False
    return not finding.severity < rule.match.min_severity


def _action_seed_for_finding(finding: FindingInput) -> str:
    """Baut einen Action-Text-Seed für den Klassifikator.

    Im S2a-MVP rufen wir die Storytelling-Engine **nicht** auf, weil
    Rule-Engine und Storytelling unabhängig laufen sollen (Tests, Pro-
    LLM-Pfad in Iteration 2). Stattdessen bauen wir einen knappen Seed
    aus den ``details``-Werten — die Heuristiken-Keywords kommen primär
    aus dem ``classifier_hint.action_keywords`` der Regel.

    Bewusst **nicht** im Seed: ``finding.tool`` und ``finding.finding_type``.
    Beispiel-Bug, gegen den das schützt: ``"dependency_auditor"`` würde
    ``"audit"`` in den Text einschleusen, was im Quick-Win-Blocklist (H3)
    steckt — und so Quick-Wins falsch unterdrücken würde.
    """
    parts = [f"{key}={value}" for key, value in finding.details.items()]
    return " ".join(parts)
