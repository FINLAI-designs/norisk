"""
test_assistant_provider — Lazy-Singleton-Slot des vereinten Assistenten, C).

Prüft die DI-Provider-Invarianten ohne GUI/Ollama:

  * Kein Service ohne registrierte Factory (Dialog außerhalb des App-Kontexts).
  * Lazy-Build erst beim ersten Zugriff, danach gecacht (genau EINE Instanz).
  * Selbstheilung: eine Instanz ohne aufgelöstes Modell wird NICHT gecacht.
  * Re-Registrierung invalidiert den Cache.
  * Factory-Fehler ist fail-soft (None statt Crash).

Author: Patrick Riederich
"""

from __future__ import annotations

import pytest

from core.assistant import provider as prov


class _FakeService:
    """Minimaler Service-Stub: trägt nur das vom Provider geprüfte ``model``."""

    def __init__(self, model: str = "llama") -> None:
        self.model = model
        self.reset_called = 0

    def reset(self) -> None:
        self.reset_called += 1


@pytest.fixture(autouse=True)
def _clean_provider():
    """Isoliert den Modul-globalen Provider-State je Test."""
    prov._factory = None
    prov._instance = None
    yield
    prov._factory = None
    prov._instance = None


def test_no_factory_returns_none():
    assert prov.get_assistant_service() is None
    assert prov.peek_assistant_service() is None


def test_factory_built_lazily_and_cached():
    calls: list[int] = []

    def factory():
        calls.append(1)
        return _FakeService("m1")

    prov.register_assistant_factory(factory)
    assert prov.peek_assistant_service() is None  # noch nicht gebaut
    svc = prov.get_assistant_service()
    assert isinstance(svc, _FakeService)
    assert prov.get_assistant_service() is svc  # gecacht, nicht neu gebaut
    assert len(calls) == 1
    assert prov.peek_assistant_service() is svc


def test_empty_model_not_cached_self_heals():
    state = {"model": ""}
    built: list[int] = []

    def factory():
        built.append(1)
        return _FakeService(state["model"])

    prov.register_assistant_factory(factory)
    first = prov.get_assistant_service()
    assert first is not None and first.model == ""
    assert prov.peek_assistant_service() is None  # leeres Modell → nicht gecacht
    # Ollama nun verfügbar → Modell aufgelöst → ab jetzt gecacht.
    state["model"] = "llama"
    second = prov.get_assistant_service()
    assert second.model == "llama"
    assert prov.peek_assistant_service() is second
    assert len(built) == 2  # bis zum Erfolg neu gebaut


def test_register_invalidates_cache():
    prov.register_assistant_factory(lambda: _FakeService("a"))
    first = prov.get_assistant_service()
    prov.register_assistant_factory(lambda: _FakeService("b"))
    assert prov.peek_assistant_service() is None
    second = prov.get_assistant_service()
    assert second is not first
    assert second.model == "b"


def test_factory_exception_returns_none():
    def boom():
        raise RuntimeError("kein Ollama")

    prov.register_assistant_factory(boom)
    assert prov.get_assistant_service() is None
    assert prov.peek_assistant_service() is None


def test_reset_clears_cache():
    prov.register_assistant_factory(lambda: _FakeService("m"))
    svc = prov.get_assistant_service()
    assert prov.peek_assistant_service() is svc
    prov.reset_assistant_service()
    assert prov.peek_assistant_service() is None
