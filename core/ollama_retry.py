"""Exponential-Backoff-Wrapper für Ollama-Calls.

Bewusst getrennt von ``core/ollama_utils.py``: ``ollama_utils`` kümmert sich um
Modell-Auswahl und Startup-Erkennung, dieses Modul kümmert sich ausschließlich
um Retry-Logik rund um einzelne LLM-Calls.

Typische Verwendung in den Pipeline-Generatoren (Stage 5a/5b):

    from core.ollama_retry import with_backoff

    entries = with_backoff(
        lambda: stage_5b.generate_aufgaben_by_subtype(chunk, topics, "buchungssatz",...)
)

``with_backoff`` retryt bei ``RuntimeError`` und ``TimeoutError`` (die beiden
Exceptions die die Stage-Module bei Ollama-Problemen werfen), lässt alle
anderen Exceptions sofort durchreichen.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from core.exceptions import NetworkError, ValidationError
from core.logger import get_logger

_log = get_logger(__name__)


DEFAULT_MAX_VERSUCHE: int = 3
DEFAULT_BASIS_DELAY_S: float = 2.0

# Exceptions die als "transient" gelten und einen Retry auslösen.
_RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ConnectionError,
    TimeoutError,
    RuntimeError,  # Stage 5a/5b werfen RuntimeError bei Ollama-Problemen
)


def with_backoff[T](
    call: Callable[[], T],
    *,
    max_versuche: int = DEFAULT_MAX_VERSUCHE,
    basis_delay_s: float = DEFAULT_BASIS_DELAY_S,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> T:
    """Führt ``call`` mit exponential-backoff-Retry aus.

    Bei einem transienten Fehler (ConnectionError, TimeoutError, RuntimeError)
    wird mit 2s, 4s, 8s … Delay neu probiert. Der Delay verdoppelt sich pro
    Fehlversuch (``basis_delay_s * 2 ** (attempt - 1)``).

    Args:
        call: Parameterlose Callable die den Ollama-Call ausführt.
        max_versuche: Maximale Anzahl Versuche inkl. Erstversuch (>= 1).
        basis_delay_s: Delay nach dem ersten Fehlversuch (Standard 2.0s).
        sleep_fn: Sleep-Funktion für Tests injizierbar (Standard ``time.sleep``).

    Returns:
        Rückgabewert von ``call``.

    Raises:
        Die zuletzt aufgetretene transiente Exception wenn alle Versuche
        fehlschlagen. Nicht-transiente Exceptions werden sofort propagiert.
    """
    if max_versuche < 1:
        raise ValidationError(f"max_versuche muss >= 1 sein, war {max_versuche}")

    letzte_exc: BaseException | None = None
    for versuch in range(1, max_versuche + 1):
        try:
            return call()
        except _RETRYABLE_EXCEPTIONS as exc:
            letzte_exc = exc
            if versuch >= max_versuche:
                _log.warning(
                    "with_backoff: Versuch %d/%d fehlgeschlagen, gebe auf: %s",
                    versuch,
                    max_versuche,
                    exc,
                )
                raise
            delay = basis_delay_s * (2 ** (versuch - 1))
            _log.warning(
                "with_backoff: Versuch %d/%d fehlgeschlagen (%s) — retry in %.1fs",
                versuch,
                max_versuche,
                exc,
                delay,
            )
            sleep_fn(delay)

    # Unerreichbar — entweder return oder raise innerhalb der Schleife.
    raise NetworkError("with_backoff: unerreichbarer Pfad") from letzte_exc
