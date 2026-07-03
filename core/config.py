"""core.config — Shim-Modul, leitet auf:mod:`core.settings` weiter.

Vor hat dieses Modul die HTTP/NVD/Agent/Ollama/Updater-Konstanten
direkt definiert. Mit dem R-Cfg-Sprint sind alle Konstanten in
:mod:`core.settings` (basiert auf ``pydantic-settings``) konsolidiert.
Dieses Shim erhaelt die bestehende Import-API
``from core.config import HTTP_DEFAULT_TIMEOUT`` byte-identisch.

Schichtzugehoerigkeit: ``core/`` (framework-agnostisch).
"""

from __future__ import annotations

from core.settings import (
    AGENT_MAX_FETCHES_PER_RUN,
    AGENT_MAX_RUNS_PER_HOUR,
    AGENT_MAX_SEARCH_RESULTS,
    HTTP_DEFAULT_RATE,
    HTTP_DEFAULT_TIMEOUT,
    HTTP_MAX_RETRIES,
    HTTP_MAX_RETRY_AFTER,
    HTTP_RETRY_BACKOFF_BASE,
    NVD_RATE_WITH_KEY,
    NVD_RATE_WITHOUT_KEY,
    OLLAMA_HOST,
    OLLAMA_MAX_RESPONSE_BYTES,
    OLLAMA_REQUEST_TIMEOUT,
    OLLAMA_SETUP_HINT_MODEL,
    OLLAMA_STARTUP_TIMEOUT,
    UPDATE_BASE_URL,
    UPDATE_CHECK_DELAY_MS,
    UPDATE_CHECK_TIMEOUT,
    UPDATE_DOWNLOAD_CHUNK_SIZE,
)

__all__ = [
    "AGENT_MAX_FETCHES_PER_RUN",
    "AGENT_MAX_RUNS_PER_HOUR",
    "AGENT_MAX_SEARCH_RESULTS",
    "HTTP_DEFAULT_RATE",
    "HTTP_DEFAULT_TIMEOUT",
    "HTTP_MAX_RETRIES",
    "HTTP_MAX_RETRY_AFTER",
    "HTTP_RETRY_BACKOFF_BASE",
    "NVD_RATE_WITHOUT_KEY",
    "NVD_RATE_WITH_KEY",
    "OLLAMA_HOST",
    "OLLAMA_MAX_RESPONSE_BYTES",
    "OLLAMA_REQUEST_TIMEOUT",
    "OLLAMA_SETUP_HINT_MODEL",
    "OLLAMA_STARTUP_TIMEOUT",
    "UPDATE_BASE_URL",
    "UPDATE_CHECK_DELAY_MS",
    "UPDATE_CHECK_TIMEOUT",
    "UPDATE_DOWNLOAD_CHUNK_SIZE",
]
