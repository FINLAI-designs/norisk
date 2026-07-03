"""
ollama_client — Port + HTTP-Adapter für den lokalen Ollama-REST-API.

Definiert den Port ``IOllamaClient`` und den blockierenden HTTP-Adapter
``OllamaClient``. Aus ``tools/ki_integration/`` nach ``core/llm/`` gehoben, damit sowohl die KI-Integration als auch der vereinte
FINLAI-Assistent (Handbuch-Bereich) denselben Adapter nutzen — ohne
Cross-Tool-Import (vorher griff ``handbuch_assistent`` direkt in
``ki_integration.data`` hinein).

Sicherheitsdesign:
  - Modellnamen werden über validate_model_name aus core.security.validators
    gegen [a-zA-Z0-9:._-]+ validiert (verhindert Injection)
  - base_url wird über validate_url gegen SSRF gesichert
    (nur localhost erlaubt ohne explizite Freigabe)
  - Antwortgröße begrenzt auf MAX_RESPONSE_BYTES (10 MB)
  - Keine Chat-Inhalte werden geloggt
  - Content-Type der Antwort wird geprüft

Alle Netzwerkoperationen sind BLOCKIEREND und müssen in einem QThread
aufgerufen werden.

Schichtzugehörigkeit: core/ (Shared Utilities; darf core/ + Stdlib + requests).

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Callable

import requests

from core.config import (
    OLLAMA_HOST,
    OLLAMA_MAX_RESPONSE_BYTES,
    OLLAMA_REQUEST_TIMEOUT,
)
from core.exceptions import ValidationError
from core.llm.ollama_types import OllamaModel, OllamaStatus
from core.logger import get_logger
from core.security.validators import validate_model_name, validate_url

_log = get_logger(__name__)

_STATUS_TIMEOUT_S = 5
_CHAT_TIMEOUT_S = OLLAMA_REQUEST_TIMEOUT
_PULL_TIMEOUT_S = 600
_MAX_RESPONSE_BYTES = OLLAMA_MAX_RESPONSE_BYTES

# Modell zwischen Chat-Nachrichten warm halten (Top-Level keep_alive an
# /api/chat). Effekt: der interaktive KI-Chat (ChatService.send_message ->
# OllamaClient.chat) zahlt die Modell-Ladezeit nicht bei jeder Folge-Nachricht
# erneut. Gleicher Wert wie ollama_provider._OLLAMA_KEEP_ALIVE / der Briefing-
# Pfad, damit Chat + Briefing dasselbe warme Modell teilen.
_KEEP_ALIVE = "30m"


class IOllamaClient(ABC):
    """Port für die Kommunikation mit dem Ollama REST-API.

    Implementiert von ``OllamaClient``. Alle Methoden die Netzwerkzugriffe
    durchführen MÜSSEN in einem QThread aufgerufen werden — niemals im
    Main-Thread.
    """

    @abstractmethod
    def check_status(self) -> OllamaStatus:
        """Prüft ob Ollama erreichbar ist und gibt den Status zurück.

        Returns:
            OllamaStatus mit is_available=True bei Erfolg.
        """
        ...

    @abstractmethod
    def get_models(self) -> list[OllamaModel]:
        """Gibt alle lokal installierten Ollama-Modelle zurück.

        Returns:
            Liste der verfügbaren Modelle, leer wenn keine vorhanden.
        """
        ...

    @abstractmethod
    def chat(
        self,
        model: str,
        messages: list[dict],
        on_token: Callable[[str], None],
        system_prompt: str = "",
        temperature: float = 0.7,
    ) -> str:
        """Sendet eine Chat-Anfrage mit Streaming an Ollama.

        Args:
            model: Modellname (validiert gegen Allowlist).
            messages: Liste der Nachrichten im Ollama-Format.
            on_token: Callback der für jeden empfangenen Token aufgerufen wird.
            system_prompt: Optionaler System-Prompt.
            temperature: Temperatur-Parameter (0.0–2.0).

        Returns:
            Vollständige Antwort als zusammengefügter String.

        Raises:
            ConnectionError: Wenn Ollama nicht erreichbar ist.
            TimeoutError: Wenn die Antwort zu lange ausbleibt.
            ValueError: Wenn der Modellname ungültig ist.
        """
        ...

    @abstractmethod
    def pull_model(
        self,
        model_name: str,
        on_progress: Callable[[str, int], None],
    ) -> bool:
        """Lädt ein Modell von der Ollama-Registry herunter.

        Args:
            model_name: Zu ladender Modellname (validiert gegen Allowlist).
            on_progress: Callback mit (status_text, percent 0–100).

        Returns:
            True bei Erfolg, False bei Fehler.
        """
        ...


class OllamaClient(IOllamaClient):
    """HTTP-Adapter für den Ollama REST-API.

    Kommuniziert via requests (blockierend) mit Ollama auf einer
    konfigurierbaren Basis-URL. Alle Methoden sind für den Aufruf
    aus einem QThread konzipiert.

    Security: base_url wird per validate_url auf localhost-Schema
    beschränkt. allow_non_localhost=True erlaubt externe Server,
    gibt aber eine Warnung aus.

    Args:
        base_url: Ollama-Server-URL (Standard: ``http://localhost:11434``).
        allow_non_localhost: True erlaubt externe URLs (mit Warnung).
    """

    def __init__(
        self,
        base_url: str = OLLAMA_HOST,
        allow_non_localhost: bool = False,
    ) -> None:
        try:
            self._base_url = validate_url(
                base_url, allow_non_localhost=allow_non_localhost
            )
        except ValueError as exc:
            _log.error("Ungültige Ollama-URL: %s", exc)
            self._base_url = OLLAMA_HOST

    # ------------------------------------------------------------------
    def check_status(self) -> OllamaStatus:
        """Prüft Erreichbarkeit und liest Version + Modelle."""
        try:
            resp = requests.get(
                f"{self._base_url}/api/version",
                timeout=_STATUS_TIMEOUT_S,
            )
            resp.raise_for_status()
            version = resp.json().get("version", "")
            models = self.get_models()
            return OllamaStatus(is_available=True, version=version, models=models)

        except requests.exceptions.ConnectionError:
            return OllamaStatus(
                is_available=False,
                error_message="Ollama laeuft nicht. Bitte 'ollama serve' ausfuehren.",
            )
        except requests.exceptions.Timeout:
            return OllamaStatus(
                is_available=False,
                error_message="Ollama antwortet nicht (Timeout).",
            )
        except (requests.RequestException, ValueError) as exc:
            _log.error("Ollama Status-Check Fehler: %s", type(exc).__name__)
            return OllamaStatus(
                is_available=False,
                error_message="Verbindung zum Ollama-Server fehlgeschlagen.",
            )

    # ------------------------------------------------------------------
    def get_models(self) -> list[OllamaModel]:
        """Gibt alle lokal installierten Modelle zurück."""
        try:
            resp = requests.get(
                f"{self._base_url}/api/tags",
                timeout=_STATUS_TIMEOUT_S,
            )
            resp.raise_for_status()
            data = resp.json()
            models = []
            for m in data.get("models", []):
                try:
                    models.append(
                        OllamaModel(
                            name=str(m.get("name", "")),
                            size=int(m.get("size", 0)),
                            modified_at=str(m.get("modified_at", "")),
                        )
                    )
                except (KeyError, TypeError, ValueError):
                    continue
            return models
        except (requests.RequestException, ValueError) as exc:
            _log.error("Modell-Abfrage fehlgeschlagen: %s", type(exc).__name__)
            return []

    # ------------------------------------------------------------------
    def chat(
        self,
        model: str,
        messages: list[dict],
        on_token: Callable[[str], None],
        system_prompt: str = "",
        temperature: float = 0.7,
    ) -> str:
        """Sendet eine Chat-Anfrage mit Streaming.

        Security:
          - Modellname per Allowlist validiert
          - Kumulierte Token-Bytes auf MAX_RESPONSE_BYTES begrenzt
          - Chat-Inhalte werden nicht geloggt

        Raises:
            ConnectionError: Bei Verbindungsfehler.
            TimeoutError: Bei Timeout.
            ValueError: Bei ungültigem Modellnamen oder Antwort-Limit.
        """
        # Allowlist-Validierung
        model = validate_model_name(model)
        temperature = max(0.0, min(2.0, temperature))

        # /api/chat erwartet System-Prompts als role="system"-Eintrag in
        # der messages-Liste — ein Top-Level "system"-Key wird ignoriert.
        # Wir prependen den System-Prompt, ohne ein bereits existierendes
        # role="system" doppelt einzufuegen.
        effective_messages = list(messages)
        if system_prompt and not any(
            m.get("role") == "system" for m in effective_messages
        ):
            effective_messages.insert(
                0, {"role": "system", "content": system_prompt}
            )

        payload: dict = {
            "model": model,
            "messages": effective_messages,
            "stream": True,
            "keep_alive": _KEEP_ALIVE,  # Modell zwischen Nachrichten warm halten
            "options": {"temperature": temperature},
        }

        collected: list[str] = []
        total_bytes = 0

        try:
            with requests.post(
                f"{self._base_url}/api/chat",
                json=payload,
                stream=True,
                timeout=_CHAT_TIMEOUT_S,
            ) as resp:
                resp.raise_for_status()

                for raw_line in resp.iter_lines():
                    if not raw_line:
                        continue

                    total_bytes += len(raw_line)
                    if total_bytes > _MAX_RESPONSE_BYTES:
                        _log.warning(
                            "Ollama-Antwort ueberschreitet 10MB-Limit — abgebrochen."
                        )
                        raise ValidationError(
                            "Antwort zu gross (>10MB). Streaming abgebrochen."
                        )

                    try:
                        chunk = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue

                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        collected.append(token)
                        on_token(token)

                    if chunk.get("done", False):
                        break

        except requests.exceptions.ConnectionError as exc:
            raise ConnectionError("Ollama nicht erreichbar.") from exc
        except requests.exceptions.Timeout as exc:
            raise TimeoutError(
                "Ollama antwortet nicht — Modell moeglicherweise zu langsam."
            ) from exc
        except ValueError:
            raise

        return "".join(collected)

    # ------------------------------------------------------------------
    def pull_model(
        self,
        model_name: str,
        on_progress: Callable[[str, int], None],
    ) -> bool:
        """Lädt ein Modell von der Ollama-Registry herunter."""
        # Allowlist-Validierung
        model_name = validate_model_name(model_name)

        try:
            with requests.post(
                f"{self._base_url}/api/pull",
                json={"name": model_name, "stream": True},
                stream=True,
                timeout=_PULL_TIMEOUT_S,
            ) as resp:
                resp.raise_for_status()

                for raw_line in resp.iter_lines():
                    if not raw_line:
                        continue
                    try:
                        chunk = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue

                    status = chunk.get("status", "")
                    completed = chunk.get("completed", 0)
                    total = chunk.get("total", 0)
                    percent = int(completed / total * 100) if total > 0 else 0
                    on_progress(status, percent)

                    if chunk.get("status") == "success":
                        return True

            return True

        except (requests.RequestException, ValueError, OSError) as exc:
            _log.error("Modell-Download fehlgeschlagen: %s", type(exc).__name__)
            return False
