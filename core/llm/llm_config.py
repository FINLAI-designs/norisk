"""llm_config — Zentrale LLM-Provider-Konfiguration (EncryptedDatabase).

Persistiert welcher Provider aktiv ist, welche Modelle pro Provider
gewählt sind, sowie Temperatur und Max-Tokens-Einstellungen.

**:** NoRisk-App ist 100% lokal. Nur Ollama
bleibt als gültige Provider-ID. Alte Werte ``openai`` oder ``anthropic``
in der DB werden beim Lesen graceful behandelt (Factory fällt auf
Ollama zurück), aber ``setze_provider`` akzeptiert sie nicht mehr.

Schichtzugehörigkeit: core/llm/ (darf core/database/ importieren).

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from core.database.encrypted_db import EncryptedDatabase
from core.exceptions import ValidationError
from core.logger import get_logger
from core.ollama_utils import DEFAULT_OLLAMA_MODEL as _DEFAULT_OLLAMA_MODEL

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# DB-Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# ---------------------------------------------------------------------------
# Schlüssel-Konstanten (nie als Magic Strings gestreut)
# ---------------------------------------------------------------------------

_KEY_PROVIDER = "active_provider"
_KEY_MODEL_PREFIX = "model:"  # z.B. "model:ollama", "model:openai"
_KEY_TEMPERATURE = "temperature"
_KEY_MAX_TOKENS = "max_tokens"


class LLMProviderConfig:
    """Zentrale LLM-Konfiguration — aus EncryptedDatabase geladen.

    Jeder Wert hat einen sinnvollen Default der zurückgegeben wird wenn
    noch nichts konfiguriert wurde.

    Defaults:
        - Provider: ``"ollama"``
        - Ollama-Modell: ``"gemma3"`` (Empfehlung; fällt auf installiertes zurück)
        - Temperatur: ``0.7``
        - Max-Tokens: ``2048``
    """

    DEFAULT_PROVIDER: str = "ollama"
    # Default-Modellname kommt aus core.ollama_utils (zentrale Quelle, R1).
    DEFAULT_OLLAMA_MODEL: str = _DEFAULT_OLLAMA_MODEL
    DEFAULT_TEMPERATURE: float = 0.7
    DEFAULT_MAX_TOKENS: int = 2048

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        """Initialisiert die Konfiguration.

        Args:
            db: EncryptedDatabase-Instanz; wenn None wird ``"llm_config"``
                als DB-Name verwendet.
        """
        self._db = db or EncryptedDatabase("llm_config")
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Provider
    # ------------------------------------------------------------------

    def aktiver_provider(self) -> str:
        """Gibt den aktiven Provider-ID zurück.

        Nach gibt es nur noch ``"ollama"``. Bestandsdaten aus
        Pre-Removal-Zeit (z. B. ``"openai"`` oder ``"anthropic"``) werden
        beim Lesen unverändert zurückgegeben, aber die Factory fällt auf
        Ollama zurück.

        Returns:
            ``"ollama"`` (oder ein Legacy-Wert).
        """
        return self._lese(_KEY_PROVIDER, self.DEFAULT_PROVIDER)

    def setze_provider(self, provider_id: str) -> None:
        """Setzt den aktiven Provider.

        Nach wird nur ``"ollama"`` akzeptiert.

        Args:
            provider_id: Muss ``"ollama"`` sein.
        """
        if provider_id != "ollama":
            _log.warning(
                "Provider-ID '%s' nicht akzeptiert — nur 'ollama' verfügbar "
                "seit ADR-INIT-012",
                provider_id,
            )
            return
        self._schreibe(_KEY_PROVIDER, provider_id)
        _log.info("LLM-Provider gesetzt: %s", provider_id)

    # ------------------------------------------------------------------
    # Modell
    # ------------------------------------------------------------------

    def aktives_modell(self, provider_id: str) -> str:
        """Gibt das konfigurierte Modell für einen Provider zurück.

        Args:
            provider_id: Provider-ID.

        Returns:
            Modellname oder Provider-spezifischer Default.
        """
        defaults = {
            "ollama": self.DEFAULT_OLLAMA_MODEL,
        }
        default = defaults.get(provider_id, "")
        return self._lese(f"{_KEY_MODEL_PREFIX}{provider_id}", default)

    def setze_modell(self, provider_id: str, model: str) -> None:
        """Setzt das Modell für einen Provider.

        Args:
            provider_id: Provider-ID.
            model: Modellname.
        """
        if not model:
            _log.warning("Leerer Modellname für Provider '%s' — ignoriert", provider_id)
            return
        self._schreibe(f"{_KEY_MODEL_PREFIX}{provider_id}", model)
        _log.info("LLM-Modell für '%s' gesetzt: %s", provider_id, model)

    # ------------------------------------------------------------------
    # Temperatur + Max-Tokens
    # ------------------------------------------------------------------

    def temperatur(self) -> float:
        """Gibt die konfigurierte Sampling-Temperatur zurück (Default 0.7).

        Returns:
            Float zwischen 0.0 und 2.0.
        """
        raw = self._lese(_KEY_TEMPERATURE, str(self.DEFAULT_TEMPERATURE))
        try:
            return float(raw)
        except ValueError:
            return self.DEFAULT_TEMPERATURE

    def setze_temperatur(self, t: float) -> None:
        """Setzt die Sampling-Temperatur.

        Args:
            t: Temperatur zwischen 0.0 und 2.0.

        Raises:
            ValueError: Wenn Temperatur außerhalb [0.0, 2.0].
        """
        if not 0.0 <= t <= 2.0:
            raise ValidationError(f"Temperatur muss zwischen 0.0 und 2.0 sein, war: {t}")
        self._schreibe(_KEY_TEMPERATURE, str(t))

    def max_tokens(self) -> int:
        """Gibt die konfigurierte maximale Token-Anzahl zurück (Default 2048).

        Returns:
            Positive Ganzzahl.
        """
        raw = self._lese(_KEY_MAX_TOKENS, str(self.DEFAULT_MAX_TOKENS))
        try:
            return max(1, int(raw))
        except ValueError:
            return self.DEFAULT_MAX_TOKENS

    def setze_max_tokens(self, t: int) -> None:
        """Setzt die maximale Token-Anzahl.

        Args:
            t: Token-Anzahl (mindestens 1).

        Raises:
            ValueError: Wenn t < 1.
        """
        if t < 1:
            raise ValidationError(f"max_tokens muss mindestens 1 sein, war: {t}")
        self._schreibe(_KEY_MAX_TOKENS, str(t))

    # ------------------------------------------------------------------
    # Interne Helpers
    # ------------------------------------------------------------------

    def _lese(self, key: str, default: str) -> str:
        try:
            with self._db.connection() as conn:
                row = conn.execute(
                    "SELECT value FROM llm_config WHERE key = ?", (key,)
                ).fetchone()
                return row[0] if row else default
        except (OSError, RuntimeError):
            _log.exception("Fehler beim Lesen von LLM-Config-Key '%s'", key)
            return default

    def _schreibe(self, key: str, value: str) -> None:
        try:
            with self._db.connection() as conn:
                conn.execute(
                    "INSERT INTO llm_config (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )
        except (OSError, RuntimeError):
            _log.exception("Fehler beim Schreiben von LLM-Config-Key '%s'", key)
