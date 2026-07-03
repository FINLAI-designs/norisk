"""llm_result — Providerunabhängige Datenmodelle für LLM-Antworten.

Schichtzugehörigkeit: core/llm/ (nur Python-Stdlib, keine Außen-Abhängigkeiten).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LLMMessage:
    """Eine Chat-Nachricht.

    Attributes:
        role: ``"system"``, ``"user"`` oder ``"assistant"``.
        content: Nachrichtentext.
    """

    role: str
    content: str


@dataclass
class LLMResult:
    """Ergebnis einer LLM-Anfrage — providerunabhängig.

    Attributes:
        content: Antwort-Text (leer wenn Fehler).
        model: Verwendetes Modell (z. B. ``"gemma3:27b"``).
        provider: Provider-ID: ``"ollama"``, ``"openai"``, ``"anthropic"``.
        tokens_input: Eingabe-Token-Anzahl (0 wenn nicht geliefert).
        tokens_output: Ausgabe-Token-Anzahl (0 wenn nicht geliefert).
        duration_ms: Antwortzeit in Millisekunden (0 wenn nicht gemessen).
        finish_reason: Abbruchgrund: ``"stop"``, ``"length"``, ``"error"``, etc.
        error: Fehlermeldung (leer wenn erfolgreich).
        success: False wenn ein Fehler aufgetreten ist.
    """

    content: str
    model: str = ""
    provider: str = ""
    tokens_input: int = 0
    tokens_output: int = 0
    duration_ms: int = 0
    finish_reason: str = ""
    error: str = ""
    success: bool = True

    @classmethod
    def fehlschlag(cls, error: str, provider: str = "", model: str = "") -> LLMResult:
        """Erstellt ein Fehler-Ergebnis.

        Args:
            error: Fehlermeldung.
            provider: Provider-ID.
            model: Modellname.

        Returns:
            LLMResult mit success=False und leerem content.
        """
        return cls(
            content="",
            error=error,
            success=False,
            provider=provider,
            model=model,
            finish_reason="error",
        )
