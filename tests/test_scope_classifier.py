"""
test_scope_classifier — Deterministische Tests für den (3-wertigen) Scope-
Klassifikator des vereinten FINLAI-Assistenten.

Schließt die vom Review (wf_de8af375) gefundene Test-Lücke: ``parse_scope_domain``
und ``make_ollama_domain_classifier`` wurden zuvor von keinem Test direkt
abgedeckt (die UnifiedAssistantService-Tests injizieren ein hartverdrahtetes
Gate und umgehen Parser + Prompt-Vertrag). Pinnt insbesondere, dass der
3-wertige Klassifikator das ``{"domain": …}``-Schema verlangt (NICHT das binäre
``{"in_scope": …}``) und alle Parser-Zweige.

Author: Patrick Riederich
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from core.guardrails.guardrails import (
    DOMAIN_HANDBOOK,
    DOMAIN_OFFTOPIC,
    DOMAIN_SECURITY,
)
from core.guardrails.prompts import SCOPE_CLASSIFIER_3WAY_SYSTEM_PROMPT
from core.guardrails.scope_classifier import (
    make_ollama_domain_classifier,
    parse_in_scope,
    parse_scope_domain,
)


class _RecordingClient:
    """IOllamaClient-Double: zeichnet den Aufruf auf, liefert eine feste Ausgabe."""

    def __init__(self, output: str) -> None:
        self._output = output
        self.calls: list[dict] = []

    def chat(
        self,
        model: str,
        messages: list[dict],
        on_token: Callable[[str], None],
        system_prompt: str = "",
        temperature: float = 0.0,
    ) -> str:
        self.calls.append(
            {
                "model": model,
                "messages": messages,
                "system_prompt": system_prompt,
                "temperature": temperature,
            }
        )
        return self._output


# ─────────────────────────────────────────────────────────────────────────────
# parse_scope_domain — alle Zweige
# ─────────────────────────────────────────────────────────────────────────────
class TestParseScopeDomain:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ('{"domain": "security"}', DOMAIN_SECURITY),
            ('{"domain": "handbook"}', DOMAIN_HANDBOOK),
            ('{"domain": "offtopic"}', DOMAIN_OFFTOPIC),
            ('{"domain":"SECURITY"}', DOMAIN_SECURITY),  # case-insensitiv
            ("<think>überlege…</think>\n{\"domain\": \"offtopic\"}", DOMAIN_OFFTOPIC),
        ],
    )
    def test_json_domain_extracted(self, raw, expected):
        assert parse_scope_domain(raw) == expected

    def test_bare_keyword_fallback(self):
        assert parse_scope_domain("Das ist klar offtopic.") == DOMAIN_OFFTOPIC

    def test_bare_takes_last_match(self):
        # Dokumentiert das bare[-1]-Verhalten (letzte Nennung gewinnt).
        assert parse_scope_domain("erst handbook, dann doch security") == DOMAIN_SECURITY

    def test_empty_returns_default(self):
        assert parse_scope_domain("") == DOMAIN_HANDBOOK

    def test_garbage_returns_default_not_offtopic(self):
        # Unklare Ausgabe → Default (Handbuch), NICHT still blocken.
        assert parse_scope_domain("???") == DOMAIN_HANDBOOK

    def test_custom_default(self):
        assert parse_scope_domain("???", default=DOMAIN_SECURITY) == DOMAIN_SECURITY

    def test_binary_shaped_output_falls_back_to_default(self):
        # Falls das Modell (fälschlich) das binäre Schema liefert: kein
        # domain-Match → Default-Domäne (kein Crash, keine Security-Fehlroute).
        assert parse_scope_domain('{"in_scope": false}') == DOMAIN_HANDBOOK
        assert parse_scope_domain('{"in_scope": true}') == DOMAIN_HANDBOOK


# ─────────────────────────────────────────────────────────────────────────────
# make_ollama_domain_classifier — Prompt-Vertrag + Roundtrip
# ─────────────────────────────────────────────────────────────────────────────
class TestMakeOllamaDomainClassifier:
    def test_uses_3way_contract_not_binary(self):
        client = _RecordingClient('{"domain": "security"}')
        classify = make_ollama_domain_classifier(client, "testmodell")  # type: ignore[arg-type]
        result = classify("Wie härte ich die Firewall?")
        assert result == DOMAIN_SECURITY
        call = client.calls[0]
        sent = call["messages"][-1]["content"]
        # Der 3-wertige Vertrag (domain) MUSS in der User-Message stehen,
        # das binäre Schema (in_scope) darf NICHT auftauchen (Review-Fix).
        assert '"domain"' in sent
        assert "in_scope" not in sent
        assert call["system_prompt"] == SCOPE_CLASSIFIER_3WAY_SYSTEM_PROMPT
        assert call["temperature"] == 0.0

    @pytest.mark.parametrize(
        ("output", "expected"),
        [
            ('{"domain": "handbook"}', DOMAIN_HANDBOOK),
            ('{"domain": "security"}', DOMAIN_SECURITY),
            ('{"domain": "offtopic"}', DOMAIN_OFFTOPIC),
        ],
    )
    def test_roundtrip_each_domain(self, output, expected):
        client = _RecordingClient(output)
        classify = make_ollama_domain_classifier(client, "m")  # type: ignore[arg-type]
        assert classify("frage") == expected

    def test_spotlighting_delimiters_present(self):
        client = _RecordingClient('{"domain": "handbook"}')
        classify = make_ollama_domain_classifier(client, "m")  # type: ignore[arg-type]
        classify("Wo finde ich die Einstellungen?")
        sent = client.calls[0]["messages"][-1]["content"]
        assert "NUTZER_ANFRAGE_DATEN" in sent  # Daten klar als DATEN markiert


# ─────────────────────────────────────────────────────────────────────────────
# parse_in_scope (binär, Legacy) — bleibt unverändert
# ─────────────────────────────────────────────────────────────────────────────
class TestParseInScopeLegacy:
    def test_json_true(self):
        assert parse_in_scope('{"in_scope": true}') is True

    def test_json_false(self):
        assert parse_in_scope('{"in_scope": false}') is False

    def test_default_on_garbage(self):
        assert parse_in_scope("???") is True  # fail-open auf System-Prompt


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
