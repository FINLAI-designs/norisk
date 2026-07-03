"""core/llm — LLM-Abstraktion für FINLAI: nur Ollama).

Unterstützte Provider:
  - OllamaProvider: Lokal (kein API-Key, einziger aktiver Provider)

Historie:
  - bis 2026-05-28: OpenAIProvider + AnthropicProvider waren zusätzlich verfügbar
  - ab 2026-05-28: durch entfernt — NoRisk-App ist 100% lokal

Empfohlenes lokales Modell: gemma3 (``ollama pull gemma3``)

Verwendung::

    from core.llm import get_llm_provider, LLMMessage

    provider = get_llm_provider
    if provider.ist_verfuegbar:
        result = provider.generate("Erkläre Python-Decorators.")
        print(result.content)

Schichtzugehörigkeit: core/ — kein GUI-Import.
"""

from __future__ import annotations

from core.llm.llm_base import AbstractLLMProvider
from core.llm.llm_config import LLMProviderConfig
from core.llm.llm_factory import LLMFactory
from core.llm.llm_result import LLMMessage, LLMResult

# ---------------------------------------------------------------------------
# Laufzeit-Cache — ein Provider pro App-Instanz
# ---------------------------------------------------------------------------

_cached_provider: AbstractLLMProvider | None = None


def get_llm_provider() -> AbstractLLMProvider:
    """Gibt den aktuell konfigurierten LLM-Provider zurück.

    Liest die Konfiguration aus ``LLMProviderConfig`` (EncryptedDatabase)
    und cached den Provider für die Laufzeit der App. Beim ersten Aufruf
    oder nach ``invalidate_llm_cache`` wird ein neuer Provider erstellt.

    Fällt auf OllamaProvider zurück wenn die Konfiguration nicht geladen
    werden kann (Abwärtskompatibilität).

    Returns:
        Konfigurierter ``AbstractLLMProvider`` (Ollama, OpenAI oder Anthropic).
    """
    global _cached_provider  # noqa: PLW0603
    if _cached_provider is not None:
        return _cached_provider

    try:
        config = LLMProviderConfig()
        _cached_provider = LLMFactory.erstelle_provider(config)
    except Exception:  # noqa: BLE001
        # Fallback: Ollama direkt (Abwärtskompatibilität)
        from core.llm.ollama_provider import OllamaProvider  # noqa: PLC0415

        _cached_provider = OllamaProvider()

    return _cached_provider


def invalidate_llm_cache() -> None:
    """Invalidiert den Provider-Cache.

    Muss nach jeder Einstellungsänderung aufgerufen werden, damit der
    nächste ``get_llm_provider``-Aufruf den neu konfigurierten Provider
    zurückgibt.
    """
    global _cached_provider  # noqa: PLW0603
    _cached_provider = None


__all__ = [
    "AbstractLLMProvider",
    "LLMFactory",
    "LLMMessage",
    "LLMProviderConfig",
    "LLMResult",
    "get_llm_provider",
    "invalidate_llm_cache",
]
