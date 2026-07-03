"""llm_factory — Factory für LLM-Provider-Instanzen.

Erstellt Provider-Instanzen basierend auf der LLMProviderConfig.
Alle Provider-Imports sind lazy (innerhalb der Methode) um zirkuläre
Abhängigkeiten zu vermeiden.

**:** NoRisk-App ist 100% lokal. Nur Ollama
bleibt als LLM-Provider — Anthropic und OpenAI wurden entfernt.
Die Factory akzeptiert unbekannte Provider-IDs (z. B. aus Altinstallationen
mit konfiguriertem ``openai`` oder ``anthropic``) graceful und fällt
auf Ollama zurück.

Schichtzugehörigkeit: core/llm/ (darf alle core/llm/ Module importieren).

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from core.llm.llm_base import AbstractLLMProvider
from core.llm.llm_config import LLMProviderConfig
from core.logger import get_logger

_log = get_logger(__name__)


class LLMFactory:
    """Factory: Erstellt LLM-Provider basierend auf der gespeicherten Konfiguration.

    Nach gibt es nur noch Ollama. Die Factory bleibt als
    Indirektion erhalten, damit eine spätere Wiedereinführung weiterer
    lokaler Provider (z. B. llama.cpp direkt) keine Aufrufer-Änderungen
    erfordert.
    """

    @staticmethod
    def erstelle_provider(config: LLMProviderConfig) -> AbstractLLMProvider:
        """Erstellt den konfigurierten LLM-Provider.

        Liest den aktiven Provider aus config; aktuell wird immer Ollama
        zurückgegeben (auch wenn die DB noch eine alte ``openai``- oder
        ``anthropic``-Konfiguration aus Pre--Zeit enthält).

        Args:
            config: LLMProviderConfig-Instanz mit gespeicherten Einstellungen.

        Returns:
            OllamaProvider-Instanz.
        """
        provider_id = config.aktiver_provider()
        if provider_id != "ollama":
            _log.info(
                "Legacy-Provider-ID '%s' in DB — auf Ollama zurückgefallen "
                "(ADR-INIT-012)",
                provider_id,
            )
        from core.llm.ollama_provider import OllamaProvider  # noqa: PLC0415

        return OllamaProvider()

    @staticmethod
    def alle_provider() -> list[AbstractLLMProvider]:
        """Gibt alle verfügbaren Provider zurück (für Einstellungen-UI).

        Nach nur noch ein Eintrag.

        Returns:
            Liste mit ``[OllamaProvider]``.
        """
        from core.llm.ollama_provider import OllamaProvider  # noqa: PLC0415

        return [OllamaProvider()]

    @staticmethod
    def erstelle_ollama() -> AbstractLLMProvider:
        """Erstellt direkt einen OllamaProvider (ohne Config-Lookup).

        Nützlich wenn explizit Ollama verwendet werden soll unabhängig
        von der gespeicherten Konfiguration.

        Returns:
            OllamaProvider-Instanz.
        """
        from core.llm.ollama_provider import OllamaProvider  # noqa: PLC0415

        return OllamaProvider()
