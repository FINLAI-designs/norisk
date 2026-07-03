"""llm_base — Abstraktes LLM-Provider-Interface (Port).

Jeder LLM-Provider implementiert dieses Interface. Aktuell gibt es
nur einen produktiven Provider: ``OllamaProvider`` (lokal). Cloud-Provider
(Anthropic, OpenAI) wurden durch entfernt.
Die `generate`-Methode ist als Convenience-Wrapper auf `chat` implementiert
und muss nicht überschrieben werden.

Schichtzugehörigkeit: core/llm/ (nur Python-Stdlib und eigene llm_result).

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from core.llm.llm_result import LLMMessage, LLMResult


class AbstractLLMProvider(ABC):
    """Port: Abstraktes LLM-Provider-Interface.

    Implementiert von:
    - OllamaProvider: Lokales Ollama (einziger produktiver Provider seit)
    """

    @abstractmethod
    def ist_verfuegbar(self) -> bool:
        """Prüft ob der Provider einsatzbereit ist.

        Für lokale Provider (Ollama): Server läuft.
        Für Cloud-Provider: API-Key vorhanden.

        Returns:
            True wenn der Provider Anfragen verarbeiten kann.
        """

    @abstractmethod
    def chat(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> LLMResult:
        """Sendet eine Chat-Anfrage (nicht-streamend).

        Args:
            messages: Nachrichtenliste mit Rollen und Inhalten.
            model: Modellname; None = Provider-Default.
            temperature: Sampling-Temperatur (0.0–2.0).
            max_tokens: Maximale Ausgabe-Token-Anzahl.

        Returns:
            LLMResult mit Antworttext und Metadaten.
        """

    @abstractmethod
    def verfuegbare_modelle(self) -> list[str]:
        """Gibt die verfügbaren Modellnamen zurück.

        Returns:
            Sortierte Liste der Modellnamen (empfohlene zuerst).
            Leere Liste wenn Provider nicht erreichbar.
        """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Anzeigename des Providers (für UI)."""

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Technische ID — aktuell nur ``"ollama"``."""

    @property
    @abstractmethod
    def ist_lokal(self) -> bool:
        """True wenn lokal (kein API-Key, kein Internet nötig)."""

    # ------------------------------------------------------------------
    # Streaming (nicht abstrakt — Default fallt auf chat zurueck)
    # ------------------------------------------------------------------

    def chat_stream(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> Iterator[str]:
        """Sendet einen Chat und yieldet Antwort-Chunks PR-B).

        Default-Verhalten: ruft:meth:`chat` synchron auf und yieldet den
        Final-Content als einen einzigen Chunk. ``OllamaProvider`` überschreibt
        das für echtes Streaming via ``stream=True`` (NDJSON).

        Args:
            messages: Nachrichtenliste mit Rollen und Inhalten.
            model: Modellname; None = Provider-Default.
            temperature: Sampling-Temperatur (0.0–2.0).
            max_tokens: Maximale Ausgabe-Token-Anzahl.

        Yields:
            Antwort-Chunks (str) in der Reihenfolge ihres Eintreffens.
            Bei Provider-Fehler wird ein einziger Chunk mit dem
            Fehler-Text (oder leer) geyielded — der Caller pruefte
            danach:meth:`chat` separat, falls ein vollstaendiges
:class:`LLMResult` mit Token-Counts gebraucht wird.

        Hinweis fuer Caller: der Iterator MUSS ausgelesen werden
        (z. B. via ``"".join(chat_stream)``), sonst bleiben
        Server-Verbindungen offen.
        """
        result = self.chat(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if result.content:
            yield result.content

    # ------------------------------------------------------------------
    # Convenience-Methode (nicht abstrakt — basiert auf chat)
    # ------------------------------------------------------------------

    def generate(
        self,
        prompt: str,
        model: str | None = None,
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> LLMResult:
        """Einfache Text-Generierung — Convenience-Wrapper über chat.

        Args:
            prompt: Benutzerprompt.
            model: Modellname; None = Provider-Default.
            system_prompt: Optionaler System-Prompt.
            temperature: Sampling-Temperatur.
            max_tokens: Maximale Ausgabe-Token-Anzahl.

        Returns:
            LLMResult mit generiertem Text.
        """
        messages: list[LLMMessage] = []
        if system_prompt:
            messages.append(LLMMessage(role="system", content=system_prompt))
        messages.append(LLMMessage(role="user", content=prompt))
        return self.chat(
            messages, model=model, temperature=temperature, max_tokens=max_tokens
        )
