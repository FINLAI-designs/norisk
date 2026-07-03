"""Tests für core.ollama_retry.with_backoff (Paket 06)."""

from __future__ import annotations

import pytest

from core.ollama_retry import with_backoff


def test_success_on_first_attempt() -> None:
    """Erfolg beim ersten Versuch — kein Retry, kein Sleep."""
    aufrufe: list[int] = []

    def _call() -> str:
        aufrufe.append(1)
        return "ok"

    sleeps: list[float] = []
    ergebnis = with_backoff(_call, sleep_fn=sleeps.append)

    assert ergebnis == "ok"
    assert len(aufrufe) == 1
    assert sleeps == []


def test_retries_twice_then_success() -> None:
    """Zweimal Fehler, dann Erfolg — genau zwei Delays (2s, 4s)."""
    aufrufe: list[int] = []

    def _call() -> str:
        aufrufe.append(1)
        if len(aufrufe) < 3:
            raise RuntimeError("Ollama busy")
        return "fertig"

    sleeps: list[float] = []
    ergebnis = with_backoff(_call, sleep_fn=sleeps.append)

    assert ergebnis == "fertig"
    assert len(aufrufe) == 3
    assert sleeps == [2.0, 4.0]


def test_three_failures_propagate_last_exception() -> None:
    """Drei Fehler in Folge — die zuletzt gesehene Exception propagiert."""
    aufrufe: list[int] = []

    def _call() -> str:
        aufrufe.append(1)
        raise ConnectionError(f"Versuch {len(aufrufe)}")

    sleeps: list[float] = []
    with pytest.raises(ConnectionError, match="Versuch 3"):
        with_backoff(_call, sleep_fn=sleeps.append)

    assert len(aufrufe) == 3
    # 2 Sleeps (nach Versuch 1 und 2, nach Versuch 3 wird geraised)
    assert sleeps == [2.0, 4.0]


def test_non_retryable_exception_propagates_immediately() -> None:
    """ValueError ist nicht retry-bar — sofort propagieren, kein Sleep."""
    aufrufe: list[int] = []

    def _call() -> str:
        aufrufe.append(1)
        raise ValueError("bad input")

    sleeps: list[float] = []
    with pytest.raises(ValueError, match="bad input"):
        with_backoff(_call, sleep_fn=sleeps.append)

    assert len(aufrufe) == 1
    assert sleeps == []


def test_timeout_error_is_retryable() -> None:
    """TimeoutError wird retryt wie ConnectionError."""
    aufrufe: list[int] = []

    def _call() -> str:
        aufrufe.append(1)
        if len(aufrufe) < 2:
            raise TimeoutError("Ollama Timeout")
        return "ok"

    sleeps: list[float] = []
    ergebnis = with_backoff(_call, sleep_fn=sleeps.append)

    assert ergebnis == "ok"
    assert len(aufrufe) == 2
    assert sleeps == [2.0]


def test_custom_max_versuche_and_basis_delay() -> None:
    """Konfigurierbare Anzahl Versuche und Basis-Delay."""
    aufrufe: list[int] = []

    def _call() -> str:
        aufrufe.append(1)
        raise RuntimeError("x")

    sleeps: list[float] = []
    with pytest.raises(RuntimeError):
        with_backoff(_call, max_versuche=4, basis_delay_s=1.0, sleep_fn=sleeps.append)

    assert len(aufrufe) == 4
    # Exponential: 1, 2, 4 (kein Sleep nach letztem Versuch)
    assert sleeps == [1.0, 2.0, 4.0]


def test_invalid_max_versuche_raises() -> None:
    """``max_versuche < 1`` wird mit ``ValueError`` abgewiesen."""
    with pytest.raises(ValueError, match="max_versuche"):
        with_backoff(lambda: "x", max_versuche=0)
