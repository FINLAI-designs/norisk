"""
core.guardrails — Tool-übergreifende Schutzschichten für den vereinten
FINLAI-Assistenten (Security-Chat + Handbuch-Assistent).

Aus ``tools/ki_integration/application/`` nach ``core/`` gehoben,
damit der im ``core/help``-Dialog eingebettete Assistent dieselbe
gehärtete Pipeline (Scope-Gate, Injection-Heuristik, Output-Filter,
CVE-Disclaimer, Security-Korpus) nutzt, ohne aus ``tools/`` zu importieren.

Module:
    guardrails — ScopeGate (3-wertig: handbook/security/offtopic),
                       ScopeVerdict, detect_injection_signals,
                       filter_security_output, filter_handbuch_output (streng),
                       ensure_cve_disclaimer, DOMAIN_*-Konstanten
    prompts — SECURITY_SYSTEM_PROMPT, build_handbuch_system_prompt,
                       SCOPE_CLASSIFIER_SYSTEM_PROMPT (binär),
                       SCOPE_CLASSIFIER_3WAY_SYSTEM_PROMPT, OFFTOPIC_REFUSAL,
                       UNIFIED_OFFTOPIC_REFUSAL, RAG-Grounding-Helfer
    scope_classifier — make_ollama_scope_classifier (binär),
                       make_ollama_domain_classifier (3-wertig)
    corpus — SecurityCorpus (kuratierter Offline-Wissenskorpus)

Schichtzugehörigkeit: core/ (Shared Utilities).
"""
