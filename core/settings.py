"""core.settings — zentrale Konfiguration via ``pydantic-settings``.

R-Cfg-Sprint (Run 2). Loest die zwei vorherigen Module
``core/config.py`` (HTTP/NVD/Agent/Ollama/Updater-Konstanten) und
``core/constants.py`` (Feature-Flags + OCR + max import-size) ab.
Beide bleiben als duenne Kompatibilitaets-Shims erhalten — Importer
``from core.config import HTTP_DEFAULT_TIMEOUT`` funktionieren weiter.

Vorteile gegenueber Magic-Constants:

* **Type-Validation** beim Modul-Load. Fehlerhafte ENV-Var
  (z. B. ``FINLAI_HTTP_DEFAULT_TIMEOUT="abc"``) bricht den Bootstrap
  hart, statt zur Laufzeit eine ``ValueError`` zu werfen.
* **ENV-Var-Overrides** ueber den Praefix ``FINLAI_`` — Deployment
  kann z. B. ``FINLAI_OLLAMA_HOST=http://internal-ollama:11434``
  setzen ohne Code-Patch.
* **Single source of truth** — ein Default-Wert, eine Quelle.

ENV-Var-Konvention: ``FINLAI_<UPPERCASE_FIELD_NAME>``. Beispiele:

.. code-block:: text

    FINLAI_HTTP_DEFAULT_TIMEOUT=30
    FINLAI_OLLAMA_HOST=http://172.17.0.1:11434
    FINLAI_ENABLE_LIGHT_THEME=true

``case_sensitive=False`` — Lowercase-Varianten greifen ebenfalls.

Schichtzugehoerigkeit: ``core/`` (framework-agnostisch).
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Aggregierte Settings fuer alle FINLAI-Konstanten.

    Felder gruppieren sich nach Domaene (HTTP / NVD / Agent / Ollama /
    Updater / Features / Import). Pro Feld ist der Default-Wert in der
    Field-Default-Position dokumentiert; ENV-Var-Overrides folgen dem
    Schema ``FINLAI_<FIELD_UPPER>``.
    """

    model_config = SettingsConfigDict(
        env_prefix="FINLAI_",
        case_sensitive=False,
        # ``extra="ignore"`` damit ein FINLAI_-Praefix-Tippfehler nicht
        # den App-Start hart bricht — wir vertrauen dem Default und
        # warnen nicht (Stille = bewusst, weil ENV-Vars typisch von
        # Operations gesetzt werden, nicht vom Code).
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # HTTP-Client (core/http_client.py)
    # ------------------------------------------------------------------

    #: Verbindungs-Timeout in Sekunden fuer externe API-Requests.
    http_default_timeout: int = 15
    #: Konservativer Default fuer unbekannte Domains (Requests pro Sekunde).
    http_default_rate: float = 2.0
    #: Maximale Anzahl Wiederholungsversuche bei ``ConnectionError`` / HTTP 429.
    http_max_retries: int = 3
    #: Basiswartezeit fuer exponentiellen Backoff zwischen Retries (Sekunden).
    http_retry_backoff_base: float = 1.0
    #: Obergrenze fuer eine einzelne ``Retry-After``-Wartezeit bei HTTP 429
    #: (Sekunden). Kappt den Wert, den ein Server (oder ein Cooldown-Endpoint)
    #: vorgibt, damit ein einzelner Retry-Sleep einen Worker-Thread nie laenger
    #: als diese Schranke blockiert. Bei ``http_max_retries`` Versuchen ist der
    #: Worst-Case-Hang ``(http_max_retries - 1) * http_max_retry_after``. Lizenz-
    #: Caller umgehen den Sleep komplett via ``retry_on_429=False``.
    http_max_retry_after: int = 60

    # ------------------------------------------------------------------
    # NVD CVE API (tools/cyber_dashboard/application/nvd_service.py)
    # ------------------------------------------------------------------

    #: Rate-Limit mit API-Key: 50 req/30s ≈ 1,67 req/s; konservativ 1,5 req/s.
    nvd_rate_with_key: float = 1.5
    #: Rate-Limit ohne API-Key: 5 req/30s ≈ 0,17 req/s; konservativ 0,15 req/s.
    nvd_rate_without_key: float = 0.15

    # ------------------------------------------------------------------
    # KI-Agenten-System
    # ------------------------------------------------------------------

    #: Maximale automatische Laeufe pro Agent und Stunde (DoS-Mitigation).
    #: Wird vom AgentScheduler durchgesetzt (sliding window, 60-Minuten-Fenster).
    agent_max_runs_per_hour: int = 4
    #: Maximale Web-Fetches pro Agent-Lauf (verhindert Burst-Requests).
    #: Counter wird pro WebFetchTool-Instanz gezaehlt (= pro Agent-Lauf).
    agent_max_fetches_per_run: int = 10
    #: Maximale DuckDuckGo-Suchergebnisse pro Suche.
    agent_max_search_results: int = 20

    # ------------------------------------------------------------------
    # Ollama (lokaler LLM-Server — kein Throttling, nur Timeouts)
    # ------------------------------------------------------------------

    #: Basis-URL des lokalen Ollama-Servers (NIEMALS hardcodiert in Modulen).
    ollama_host: str = "http://localhost:11434"
    #: Modell-Empfehlung (REAL existierend) fuer Setup-Anleitungen und Fehler-
    #: meldungen.: 'qwen3.5' existiert nicht. 2026-06-25 (OSS-Rollout):
    #: 'gemma3:4b' empfohlen — leichtes Modell fuer schwache Geraete, passt zum
    #: DEFAULT_OLLAMA_MODEL='gemma3'.
    ollama_setup_hint_model: str = "gemma3:4b"
    #: Maximale Wartezeit beim Starten von Ollama.
    ollama_startup_timeout: int = 30
    #: Timeout fuer LLM-Chat-Requests (LLM-Antworten koennen lang dauern).
    ollama_request_timeout: int = 120
    #: Maximale Antwortgroesse des Ollama-Servers (verhindert Memory-Overflow).
    ollama_max_response_bytes: int = 10_485_760  # 10 MB

    # ------------------------------------------------------------------
    # Auto-Updater (core/updater.py)
    # ------------------------------------------------------------------

    #: Basis-URL des Update-Servers. Im veroeffentlichten Open-Source-Build
    #: bewusst LEER -> kein Phone-Home, der Auto-Update-Check wird uebersprungen
    #: / F7, "100% lokal"). Kommerzielle bzw. White-Label-Builds
    #: setzen den Endpunkt ueber die Umgebungsvariable ``FINLAI_UPDATE_BASE_URL``
    #: oder per ``AppConfig.update_url``-Override (eigener Server).
    update_base_url: str = ""
    #: Timeout fuer die Update-Verfuegbarkeitspruefung (kurz, blockiert nicht).
    update_check_timeout: int = 5
    #: Chunk-Groesse beim Streaming-Download (64 KiB).
    update_download_chunk_size: int = 65_536
    #: Verzoegerung nach App-Start bevor Update-Check startet (ms).
    update_check_delay_ms: int = 3_000

    # ------------------------------------------------------------------
    # Feature-Flags (vorher core/constants.py)
    # ------------------------------------------------------------------

    #: Light-Theme (Hell-Modus) aktivieren. Im Release-Build typisch False
    #: weil das Hell-Theme noch nicht produktiv getestet ist.
    enable_light_theme: bool = False

    #: PaddleOCR aktivieren (Kaskade Ebene 1 — schnell, ~1-2 GB VRAM, CPU-Fallback).
    ocr_paddle_enabled: bool = True
    #: Chandra OCR2 aktivieren (Kaskade Ebene 2 — benoetigt ~6 GB freien VRAM).
    ocr_chandra_enabled: bool = True
    #: Ollama Vision aktivieren (Kaskade Ebene 3 — kein GPU noetig).
    ocr_ollama_enabled: bool = True
    #: Tesseract aktivieren (Kaskade Ebene 4 — letzter Fallback, CPU-only).
    ocr_tesseract_enabled: bool = True

    # ------------------------------------------------------------------
    # Import / File-Handling (vorher core/constants.py)
    # ------------------------------------------------------------------

    #: Maximale Dateigroesse fuer Imports — Schutz vor sehr grossen Dateien.
    max_import_file_size: int = 52_428_800  # 50 MB


#: Modul-Singleton. Bei Modul-Load einmalig instanziiert, alle ENV-Vars
#: werden hier ausgewertet. Subsequent-Reads gehen ohne ENV-Lookup.
settings = Settings()


# ---------------------------------------------------------------------------
# Backward-Compat: Module-Level-Konstanten
# ---------------------------------------------------------------------------
# Bestehende Importer ``from core.config import HTTP_DEFAULT_TIMEOUT`` und
# ``from core.constants import ENABLE_LIGHT_THEME`` funktionieren weiter,
# weil ``core/config.py`` und ``core/constants.py`` diese Konstanten von
# hier re-exportieren.

# HTTP
HTTP_DEFAULT_TIMEOUT: int = settings.http_default_timeout
HTTP_DEFAULT_RATE: float = settings.http_default_rate
HTTP_MAX_RETRIES: int = settings.http_max_retries
HTTP_RETRY_BACKOFF_BASE: float = settings.http_retry_backoff_base
HTTP_MAX_RETRY_AFTER: int = settings.http_max_retry_after

# NVD
NVD_RATE_WITH_KEY: float = settings.nvd_rate_with_key
NVD_RATE_WITHOUT_KEY: float = settings.nvd_rate_without_key

# Agent
AGENT_MAX_RUNS_PER_HOUR: int = settings.agent_max_runs_per_hour
AGENT_MAX_FETCHES_PER_RUN: int = settings.agent_max_fetches_per_run
AGENT_MAX_SEARCH_RESULTS: int = settings.agent_max_search_results

# Ollama
OLLAMA_HOST: str = settings.ollama_host
OLLAMA_SETUP_HINT_MODEL: str = settings.ollama_setup_hint_model
OLLAMA_STARTUP_TIMEOUT: int = settings.ollama_startup_timeout
OLLAMA_REQUEST_TIMEOUT: int = settings.ollama_request_timeout
OLLAMA_MAX_RESPONSE_BYTES: int = settings.ollama_max_response_bytes

# Updater
UPDATE_BASE_URL: str = settings.update_base_url
UPDATE_CHECK_TIMEOUT: int = settings.update_check_timeout
UPDATE_DOWNLOAD_CHUNK_SIZE: int = settings.update_download_chunk_size
UPDATE_CHECK_DELAY_MS: int = settings.update_check_delay_ms

# Features (vorher core/constants.py)
ENABLE_LIGHT_THEME: bool = settings.enable_light_theme
OCR_PADDLE_ENABLED: bool = settings.ocr_paddle_enabled
OCR_CHANDRA_ENABLED: bool = settings.ocr_chandra_enabled
OCR_OLLAMA_ENABLED: bool = settings.ocr_ollama_enabled
OCR_TESSERACT_ENABLED: bool = settings.ocr_tesseract_enabled

# Import (vorher core/constants.py)
MAX_IMPORT_FILE_SIZE: int = settings.max_import_file_size


__all__ = [
    "AGENT_MAX_FETCHES_PER_RUN",
    "AGENT_MAX_RUNS_PER_HOUR",
    "AGENT_MAX_SEARCH_RESULTS",
    "ENABLE_LIGHT_THEME",
    "HTTP_DEFAULT_RATE",
    "HTTP_DEFAULT_TIMEOUT",
    "HTTP_MAX_RETRIES",
    "HTTP_MAX_RETRY_AFTER",
    "HTTP_RETRY_BACKOFF_BASE",
    "MAX_IMPORT_FILE_SIZE",
    "NVD_RATE_WITHOUT_KEY",
    "NVD_RATE_WITH_KEY",
    "OCR_CHANDRA_ENABLED",
    "OCR_OLLAMA_ENABLED",
    "OCR_PADDLE_ENABLED",
    "OCR_TESSERACT_ENABLED",
    "OLLAMA_HOST",
    "OLLAMA_MAX_RESPONSE_BYTES",
    "OLLAMA_REQUEST_TIMEOUT",
    "OLLAMA_SETUP_HINT_MODEL",
    "OLLAMA_STARTUP_TIMEOUT",
    "Settings",
    "UPDATE_BASE_URL",
    "UPDATE_CHECK_DELAY_MS",
    "UPDATE_CHECK_TIMEOUT",
    "UPDATE_DOWNLOAD_CHUNK_SIZE",
    "settings",
]
