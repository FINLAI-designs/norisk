"""core/rules — Regel-Engine für KI-Todos (Sprint S2a).

Schicht 4 (Action) der Information-Value-Strategie. Wandelt Findings
aus Scanner-Tools (cert_monitor, api_security, network_scanner,
csaf_advisor, dependency_auditor) in konkrete, klassifizierte Aufgaben
um — ohne LLM-Aufruf, rein regel-basiert (AI_TODO Iteration 1).

Public API:
  -:class:`models.Rule` — Pydantic-Modell für eine Regel
  -:class:`models.RuleAction` — gerendertes Match-Ergebnis
  -:func:`rule_engine.RuleEngine.load_directory`
  -:func:`rule_engine.RuleEngine.evaluate`
  -:func:`classifier.classify` — H1–H12 → quick / mittel / langfrist

Schichtzugehörigkeit: core/ — kein PySide6, keine DB-Zugriffe.
"""
