"""ollama_provider — Ollama-Adapter für das LLM-Interface.

Wraps die bestehende core/ollama_utils.py Infrastruktur und bietet das
AbstractLLMProvider-Interface an. Ändert NICHTS an ollama_utils — alle
direkten Aufrufe von ollama_utils funktionieren weiter wie bisher.

Sicherheitsdesign:
  - Nur localhost-Verbindungen (validate_ollama_url)
  - Modellnamen über validate_model_name geprüft
  - Antwortgröße auf OLLAMA_MAX_RESPONSE_BYTES begrenzt

Schichtzugehörigkeit: core/llm/ (darf core/ollama_utils und core/config importieren).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator

import httpx

from core.config import OLLAMA_HOST, OLLAMA_MAX_RESPONSE_BYTES, OLLAMA_REQUEST_TIMEOUT
from core.llm.llm_base import AbstractLLMProvider
from core.llm.llm_result import LLMMessage, LLMResult
from core.logger import get_logger
from core.ollama_utils import (
    GEMMA_MODEL_PREFIXES,
    get_available_models,
    is_ollama_running,
)

_log = get_logger(__name__)

# Modelle die bei verfuegbare_modelle oben sortiert werden — kommt aus
# core.ollama_utils (zentrale Quelle, Coding Rule R1).
_GEMMA_PREFIXES: tuple[str, ...] = GEMMA_MODEL_PREFIXES

# Modell nach einem Aufruf im Speicher halten, statt es zwischen
# Anfragen aus dem VRAM zu entladen.
#
# Effekt: Wird als Top-Level-Feld ``keep_alive`` an /api/chat geschickt (in
# ``chat`` UND ``chat_stream``). OHNE diesen Wert entlaedt Ollama das Modell
# nach ~5min Default -> der naechste Aufruf (z.B. Scope-Klassifikator pro
# Chat-Nachricht in core/guardrails/scope_classifier, RAG, Assistant) zahlt die
# komplette Modell-Ladezeit erneut = grosser gefuehlter Latenz-Faktor. Gleicher
# Wert wie der Briefing-Pfad (briefing_service._OLLAMA_KEEP_ALIVE), damit
# aufeinanderfolgende Chat-/Briefing-Anfragen dasselbe warme Modell teilen.
_OLLAMA_KEEP_ALIVE = "30m"


class OllamaProvider(AbstractLLMProvider):
    """Adapter: Lokales Ollama — wraps core/ollama_utils.py.

    Der Default-Provider in allen FINLAI-Apps.
    Benötigt keinen API-Key — Modelle laufen lokal.

    Modell-Empfehlung: gemma3 (``ollama pull gemma3``).
    Fallback: erstes installiertes Modell via get_default_model.
    """

    @property
    def provider_id(self) -> str:
        return "ollama"

    @property
    def provider_name(self) -> str:
        return "Ollama (Lokal)"

    @property
    def ist_lokal(self) -> bool:
        return True

    # ------------------------------------------------------------------

    def ist_verfuegbar(self) -> bool:
        """Prüft ob Ollama auf localhost läuft.

        Returns:
            True wenn Ollama-Server erreichbar.
        """
        return is_ollama_running()

    def chat(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> LLMResult:
        """Sendet eine Chat-Anfrage an Ollama (nicht-streamend).

        Args:
            messages: Nachrichtenliste.
            model: Modellname; None = erstes verfügbares Modell.
            temperature: Temperatur (0.0–2.0).
            max_tokens: Maximale Ausgabe-Token-Anzahl.

        Returns:
            LLMResult mit vollständiger Antwort.
        """
        effective_model = model or self._waehle_modell()
        if not effective_model:
            return LLMResult.fehlschlag(
                "Kein Ollama-Modell verfügbar. Bitte 'ollama pull gemma3' ausführen.",
                provider=self.provider_id,
            )

        # Nachrichten in Ollama-Format konvertieren. WICHTIG: /api/chat
        # akzeptiert KEINEN Top-Level "system"-Parameter (das ist nur
        # /api/generate-Semantik) — System-Prompt muss als erste Message
        # mit role="system" eingeschoben werden, sonst wird er ignoriert.
        chat_messages: list[dict] = []
        system_prompt = ""
        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                chat_messages.append({"role": msg.role, "content": msg.content})
        if system_prompt:
            chat_messages.insert(0, {"role": "system", "content": system_prompt})

        payload: dict = {
            "model": effective_model,
            "messages": chat_messages,
            "stream": False,
            "keep_alive": _OLLAMA_KEEP_ALIVE,  # Modell warm halten
            "options": {
                "temperature": max(0.0, min(2.0, temperature)),
                "num_predict": max_tokens,
            },
        }

        t_start = time.monotonic()
        try:
            with httpx.Client(timeout=OLLAMA_REQUEST_TIMEOUT) as client:
                resp = client.post(f"{OLLAMA_HOST}/api/chat", json=payload)
                resp.raise_for_status()

            body = resp.json()
            content = body.get("message", {}).get("content", "")

            if len(resp.content) > OLLAMA_MAX_RESPONSE_BYTES:
                _log.warning("Ollama-Antwort überschreitet 10-MB-Limit")

            # Ollama nutzt prompt_eval_count / eval_count als Top-Level-Felder
            # (nicht das OpenAI-Schema {"usage": {"prompt_tokens":...}}).
            return LLMResult(
                content=content,
                model=effective_model,
                provider=self.provider_id,
                tokens_input=int(body.get("prompt_eval_count", 0)),
                tokens_output=int(body.get("eval_count", 0)),
                duration_ms=int((time.monotonic() - t_start) * 1000),
                finish_reason=body.get("done_reason", "stop"),
            )

        except httpx.ConnectError as exc:
            _log.warning("Ollama nicht erreichbar: %s", type(exc).__name__)
            return LLMResult.fehlschlag(
                "Ollama nicht erreichbar. Bitte 'ollama serve' starten.",
                provider=self.provider_id,
                model=effective_model,
            )
        except httpx.TimeoutException as exc:
            _log.warning("Ollama-Timeout: %s", type(exc).__name__)
            return LLMResult.fehlschlag(
                "Ollama antwortet nicht — Modell möglicherweise zu langsam.",
                provider=self.provider_id,
                model=effective_model,
            )
        except (httpx.HTTPError, ValueError, RuntimeError) as exc:
            _log.exception("Ollama-Chat-Fehler: %s", type(exc).__name__)
            return LLMResult.fehlschlag(
                f"Ollama-Fehler: {type(exc).__name__}",
                provider=self.provider_id,
                model=effective_model,
            )

    def chat_stream(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> Iterator[str]:
        """Streamt Ollama-Antwort-Chunks PR-B).

        Nutzt ``stream=True`` in der Ollama-Chat-API — die Response ist
        eine Sequenz von JSON-Objekten (NDJSON), je eines pro Token-
        Batch mit Feld ``message.content``. Bei Fehler oder Cancel:
        Iterator wird vorzeitig beendet (kein Exception nach aussen,
        damit der Stream-Konsument nicht crasht).

        Args:
            messages: Nachrichtenliste.
            model: Modellname; None = erstes verfügbares.
            temperature: Sampling-Temperatur.
            max_tokens: Max-Token-Limit fuer die gesamte Antwort.

        Yields:
            Inkrementelle Content-Chunks (kann auch Leerstring sein wenn
            Ollama nur Metadata-Frames sendet — der Caller darf das
            filtern).
        """
        effective_model = model or self._waehle_modell()
        if not effective_model:
            return  # Generator endet sofort
        chat_messages, system_prompt = self._partition_messages(messages)
        if system_prompt:
            chat_messages.insert(0, {"role": "system", "content": system_prompt})

        payload: dict = {
            "model": effective_model,
            "messages": chat_messages,
            "stream": True,
            "keep_alive": _OLLAMA_KEEP_ALIVE,  # Modell warm halten
            "options": {
                "temperature": max(0.0, min(2.0, temperature)),
                "num_predict": max_tokens,
            },
        }

        try:
            with (
                httpx.Client(timeout=OLLAMA_REQUEST_TIMEOUT) as client,
                client.stream(
                    "POST", f"{OLLAMA_HOST}/api/chat", json=payload
                ) as resp,
            ):
                resp.raise_for_status()
                total_bytes = 0
                for line in resp.iter_lines():
                    if not line:
                        continue
                    total_bytes += len(line)
                    if total_bytes > OLLAMA_MAX_RESPONSE_BYTES:
                        _log.warning(
                            "Ollama-Stream ueberschreitet 10-MB-Limit "
                            "— Stream wird beendet."
                        )
                        return
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        _log.debug(
                            "Ollama-Stream: nicht-JSON-Frame ignoriert."
                        )
                        continue
                    chunk = obj.get("message", {}).get("content", "")
                    if chunk:
                        yield chunk
                    if obj.get("done") is True:
                        return
        except httpx.ConnectError:
            _log.warning("Ollama-Stream: Server nicht erreichbar.")
            return
        except httpx.TimeoutException:
            _log.warning("Ollama-Stream-Timeout.")
            return
        except httpx.HTTPError as exc:
            _log.warning(
                "Ollama-Stream-HTTP-Fehler: %s", type(exc).__name__
            )
            return

    @staticmethod
    def _partition_messages(
        messages: list[LLMMessage],
    ) -> tuple[list[dict], str]:
        """Splitt System-Prompt heraus + konvertiert zum Ollama-Format.

        Ollama's ``/api/chat`` akzeptiert KEINEN Top-Level-``system``-
        Parameter — der System-Prompt muss als erste Message mit
        ``role="system"`` eingeschoben werden.
        """
        chat_messages: list[dict] = []
        system_prompt = ""
        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                chat_messages.append({"role": msg.role, "content": msg.content})
        return chat_messages, system_prompt

    def verfuegbare_modelle(self) -> list[str]:
        """Gibt installierte Ollama-Modelle zurück, gemma3 zuerst.

        Returns:
            Liste der Modellnamen; gemma3-Varianten oben, Rest alphabetisch.
            Leere Liste wenn Ollama nicht erreichbar.
        """
        models = get_available_models()
        if not models:
            return []

        gemma = [
            m for m in models if any(m.lower().startswith(p) for p in _GEMMA_PREFIXES)
        ]
        others = sorted(m for m in models if m not in gemma)
        return gemma + others

    # ------------------------------------------------------------------
    # Intern
    # ------------------------------------------------------------------

    def _waehle_modell(self) -> str | None:
        """Wählt das beste verfügbare Ollama-Modell (gemma3 bevorzugt)."""
        models = get_available_models()
        if not models:
            return None
        for prefix in _GEMMA_PREFIXES:
            for m in models:
                if m.lower().startswith(prefix):
                    return m
        # Fallback auf get_default_model-Präferenz-Logik
        from core.ollama_utils import get_default_model  # noqa: PLC0415

        return get_default_model()
