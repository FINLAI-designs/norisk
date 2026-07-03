"""tests/test_llm_providers.py — Unit-Tests für core/llm/ Multi-Provider-System.

Alle HTTP-Calls sind gemockt — keine echten API-Anfragen nötig.
Kein GUI-Import, kein Ollama-Service benötigt.

Author: Patrick Riederich
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.llm.llm_base import AbstractLLMProvider
from core.llm.llm_result import LLMMessage, LLMResult

# ---------------------------------------------------------------------------
# Fake-Provider für Tests
# ---------------------------------------------------------------------------


class FakeLLMProvider(AbstractLLMProvider):
    """In-Memory Fake-Provider — kein Netzwerk, kein SecureStorage."""

    def __init__(self, antwort: str = "Test-Antwort", verfuegbar: bool = True) -> None:
        self._antwort = antwort
        self._verfuegbar = verfuegbar

    def ist_verfuegbar(self) -> bool:
        return self._verfuegbar

    def chat(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> LLMResult:
        if not self._verfuegbar:
            return LLMResult.fehlschlag("Provider nicht verfügbar", provider="fake")
        return LLMResult(
            content=self._antwort,
            model=model or "fake-model",
            provider="fake",
            finish_reason="stop",
        )

    def verfuegbare_modelle(self) -> list[str]:
        return ["fake-model", "fake-model-2"]

    @property
    def provider_name(self) -> str:
        return "Fake Provider"

    @property
    def provider_id(self) -> str:
        return "fake"

    @property
    def ist_lokal(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# TestLLMResult
# ---------------------------------------------------------------------------


class TestLLMResult:
    def test_erfolg_felder(self) -> None:
        r = LLMResult(content="Hallo", model="gemma3", provider="ollama")
        assert r.success is True
        assert r.content == "Hallo"
        assert r.error == ""

    def test_fehlschlag_factory(self) -> None:
        r = LLMResult.fehlschlag("Verbindungsfehler", provider="ollama", model="gemma3")
        assert r.success is False
        assert r.content == ""
        assert r.error == "Verbindungsfehler"
        assert r.finish_reason == "error"
        assert r.provider == "ollama"
        assert r.model == "gemma3"

    def test_fehlschlag_defaults(self) -> None:
        r = LLMResult.fehlschlag("Fehler")
        assert r.provider == ""
        assert r.model == ""


# ---------------------------------------------------------------------------
# TestLLMFactory
# ---------------------------------------------------------------------------


class TestLLMFactory:
    def test_default_ist_ollama(self) -> None:
        from core.llm.llm_config import LLMProviderConfig
        from core.llm.llm_factory import LLMFactory

        config = MagicMock(spec=LLMProviderConfig)
        config.aktiver_provider.return_value = "ollama"
        provider = LLMFactory.erstelle_provider(config)
        assert provider.provider_id == "ollama"

    def test_legacy_openai_id_faellt_auf_ollama_zurueck(self) -> None:
        """: Legacy-DBs mit konfiguriertem ``openai`` werden auf Ollama gemappt."""
        from core.llm.llm_config import LLMProviderConfig
        from core.llm.llm_factory import LLMFactory

        config = MagicMock(spec=LLMProviderConfig)
        config.aktiver_provider.return_value = "openai"
        provider = LLMFactory.erstelle_provider(config)
        assert provider.provider_id == "ollama"

    def test_legacy_anthropic_id_faellt_auf_ollama_zurueck(self) -> None:
        """: Legacy-DBs mit konfiguriertem ``anthropic`` werden auf Ollama gemappt."""
        from core.llm.llm_config import LLMProviderConfig
        from core.llm.llm_factory import LLMFactory

        config = MagicMock(spec=LLMProviderConfig)
        config.aktiver_provider.return_value = "anthropic"
        provider = LLMFactory.erstelle_provider(config)
        assert provider.provider_id == "ollama"

    def test_alle_provider_nur_ollama(self) -> None:
        """: nur noch Ollama in der Provider-Liste."""
        from core.llm.llm_factory import LLMFactory

        providers = LLMFactory.alle_provider()
        ids = [p.provider_id for p in providers]
        assert ids == ["ollama"]

    def test_unbekannter_provider_faellt_auf_ollama_zurueck(self) -> None:
        from core.llm.llm_config import LLMProviderConfig
        from core.llm.llm_factory import LLMFactory

        config = MagicMock(spec=LLMProviderConfig)
        config.aktiver_provider.return_value = "unbekannt"
        provider = LLMFactory.erstelle_provider(config)
        assert provider.provider_id == "ollama"


# ---------------------------------------------------------------------------
# TestOllamaProvider
# ---------------------------------------------------------------------------


class TestOllamaProvider:
    def test_provider_id(self) -> None:
        from core.llm.ollama_provider import OllamaProvider

        p = OllamaProvider()
        assert p.provider_id == "ollama"

    def test_ist_lokal(self) -> None:
        from core.llm.ollama_provider import OllamaProvider

        assert OllamaProvider().ist_lokal is True

    def test_nicht_verfuegbar_wenn_offline(self) -> None:
        from core.llm.ollama_provider import OllamaProvider

        with patch("core.llm.ollama_provider.is_ollama_running", return_value=False):
            p = OllamaProvider()
            assert p.ist_verfuegbar() is False

    def test_verfuegbar_wenn_online(self) -> None:
        from core.llm.ollama_provider import OllamaProvider

        with patch("core.llm.ollama_provider.is_ollama_running", return_value=True):
            p = OllamaProvider()
            assert p.ist_verfuegbar() is True

    def test_chat_fehlschlag_wenn_kein_modell(self) -> None:
        from core.llm.ollama_provider import OllamaProvider

        with patch("core.llm.ollama_provider.get_available_models", return_value=[]):
            p = OllamaProvider()
            result = p.chat([LLMMessage(role="user", content="Hallo")])
            assert result.success is False

    def test_gemma3_priorisiert_in_sortierung(self) -> None:
        from core.llm.ollama_provider import OllamaProvider

        with patch(
            "core.llm.ollama_provider.get_available_models",
            return_value=["llama3", "gemma3:27b", "mistral", "gemma3"],
        ):
            p = OllamaProvider()
            modelle = p.verfuegbare_modelle()
            # gemma3-Varianten müssen zuerst kommen
            assert modelle[0].startswith("gemma3") or modelle[1].startswith("gemma3")
            assert "llama3" in modelle
            assert "mistral" in modelle


# ---------------------------------------------------------------------------
# OpenAIProvider + AnthropicProvider — durch entfernt.
# Die Klassen existieren nicht mehr; entsprechende Tests wurden gestrichen.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# TestLLMConfig
# ---------------------------------------------------------------------------


class TestLLMConfig:
    """Tests für LLMProviderConfig mit echten EncryptedDatabase-Instanzen."""

    def test_default_provider_ist_ollama(self) -> None:
        from core.database.encrypted_db import EncryptedDatabase
        from core.llm.llm_config import LLMProviderConfig

        db = EncryptedDatabase("test_llm_cfg_default")
        config = LLMProviderConfig(db=db)
        assert config.aktiver_provider() == "ollama"

    def test_provider_wechsel_persistiert(self) -> None:
        """: setze_provider akzeptiert nur ``ollama``; alles andere wird ignoriert."""
        from core.database.encrypted_db import EncryptedDatabase
        from core.llm.llm_config import LLMProviderConfig

        db = EncryptedDatabase("test_llm_cfg_wechsel")
        config = LLMProviderConfig(db=db)
        config.setze_provider("ollama")
        assert config.aktiver_provider() == "ollama"

        # Versuch eine Legacy-ID zu setzen → wird ignoriert (Log-Warnung)
        config.setze_provider("openai")
        assert config.aktiver_provider() == "ollama"

        # Neue Instanz mit selber DB → Wert muss persistent sein
        config2 = LLMProviderConfig(db=db)
        assert config2.aktiver_provider() == "ollama"

    def test_modell_pro_provider(self) -> None:
        """: aktives_modell für Ollama; Legacy-IDs liefern leeren Default."""
        from core.database.encrypted_db import EncryptedDatabase
        from core.llm.llm_config import LLMProviderConfig

        db = EncryptedDatabase("test_llm_cfg_modell")
        config = LLMProviderConfig(db=db)
        # Ollama-Modell setzbar und auslesbar
        config.setze_modell("ollama", "gemma3:latest")
        assert config.aktives_modell("ollama") == "gemma3:latest"
        # Legacy-Provider-ID hat keinen Default mehr → leere Strings
        assert config.aktives_modell("openai") == ""
        assert config.aktives_modell("anthropic") == ""

        # Aufräumen
        config.setze_modell("ollama", LLMProviderConfig.DEFAULT_OLLAMA_MODEL)

    def test_temperatur_default_und_setzen(self) -> None:
        from core.database.encrypted_db import EncryptedDatabase
        from core.llm.llm_config import LLMProviderConfig

        db = EncryptedDatabase("test_llm_cfg_temp")
        config = LLMProviderConfig(db=db)
        config.setze_temperatur(LLMProviderConfig.DEFAULT_TEMPERATURE)  # Reset
        assert config.temperatur() == pytest.approx(
            LLMProviderConfig.DEFAULT_TEMPERATURE
        )
        config.setze_temperatur(1.2)
        assert config.temperatur() == pytest.approx(1.2)

        # Aufräumen
        config.setze_temperatur(LLMProviderConfig.DEFAULT_TEMPERATURE)

    def test_ungueltige_provider_id_ignoriert(self) -> None:
        """Sowohl unbekannte IDs als auch Legacy-Cloud-IDs werden ignoriert."""
        from core.database.encrypted_db import EncryptedDatabase
        from core.llm.llm_config import LLMProviderConfig

        db = EncryptedDatabase("test_llm_cfg_invalid")
        config = LLMProviderConfig(db=db)
        # Provider sicherstellen dass wir bei ollama starten
        config.setze_provider("ollama")
        config.setze_provider("ungueltig")
        config.setze_provider("openai")  # Legacy
        config.setze_provider("anthropic")  # Legacy
        # Keiner dieser Calls überschreibt — bleibt ollama
        assert config.aktiver_provider() == "ollama"


# ---------------------------------------------------------------------------
# TestCacheInvalidierung
# ---------------------------------------------------------------------------


class TestCacheInvalidierung:
    def test_cache_wird_invalidiert(self) -> None:
        import core.llm as llm_module

        # Cache leeren
        llm_module._cached_provider = None

        with (
            patch("core.llm.LLMProviderConfig") as mock_cfg_cls,
            patch("core.llm.LLMFactory") as mock_factory,
        ):
            fake = FakeLLMProvider()
            mock_factory.erstelle_provider.return_value = fake
            mock_cfg_cls.return_value = MagicMock()

            p1 = llm_module.get_llm_provider()
            p2 = llm_module.get_llm_provider()
            # Zweiter Aufruf nutzt Cache → Factory nur einmal aufgerufen
            assert mock_factory.erstelle_provider.call_count == 1
            assert p1 is p2

            # Nach Invalidierung: neuer Provider
            llm_module.invalidate_llm_cache()
            llm_module.get_llm_provider()
            assert mock_factory.erstelle_provider.call_count == 2

        # Aufräumen
        llm_module._cached_provider = None

    def test_get_llm_provider_faellt_auf_ollama_zurueck_bei_fehler(self) -> None:
        import core.llm as llm_module

        llm_module._cached_provider = None

        with patch("core.llm.LLMProviderConfig", side_effect=RuntimeError("DB fehlt")):
            p = llm_module.get_llm_provider()
            assert p.provider_id == "ollama"

        llm_module._cached_provider = None


# ---------------------------------------------------------------------------
# TestFakeProvider (Fake selbst validieren)
# ---------------------------------------------------------------------------


class TestFakeProvider:
    def test_generate_convenience(self) -> None:
        p = FakeLLMProvider(antwort="Hallo Welt")
        result = p.generate("Sag Hallo")
        assert result.success is True
        assert result.content == "Hallo Welt"

    def test_nicht_verfuegbar_gibt_fehlschlag(self) -> None:
        p = FakeLLMProvider(verfuegbar=False)
        result = p.chat([LLMMessage(role="user", content="Test")])
        assert result.success is False


# ---------------------------------------------------------------------------
# ProviderClientAdapter — entfernt-sweep
# Begruendung: Adapter war nur fuer den OpenAI/Anthropic-Pfad in
# services.py noetig. Seit liefert get_llm_provider immer
# OllamaProvider; der else-Branch in services.py ist
# unerreichbar. Datei + Tests entfallen mit dem Cleanup.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# PR-B: chat_stream
# ---------------------------------------------------------------------------


class TestAbstractProviderChatStream:
    """Default-Implementierung yieldet einen Chunk aus ``chat``."""

    def test_default_yields_full_content_as_single_chunk(self) -> None:
        provider = FakeLLMProvider(antwort="Hallo Welt")
        chunks = list(
            provider.chat_stream([LLMMessage(role="user", content="x")])
        )
        assert chunks == ["Hallo Welt"]

    def test_default_yields_nothing_when_provider_unavailable(self) -> None:
        provider = FakeLLMProvider(verfuegbar=False)
        chunks = list(
            provider.chat_stream([LLMMessage(role="user", content="x")])
        )
        # FakeProvider liefert ein fehlschlag-Result mit content=""
        assert chunks == []


class TestOllamaChatStream:
    """OllamaProvider.chat_stream — NDJSON-Parser."""

    def test_stream_yields_message_content_chunks(self, monkeypatch) -> None:
        """Mocked NDJSON-Response → Chunks werden korrekt extrahiert."""
        from core.llm import ollama_provider as op_mod

        class _MockResp:
            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                pass

            def raise_for_status(self) -> None:
                pass

            def iter_lines(self):
                yield (
                    '{"message":{"role":"assistant","content":"Hallo "},'
                    '"done":false}'
                )
                yield (
                    '{"message":{"role":"assistant","content":"Welt"},'
                    '"done":false}'
                )
                yield (
                    '{"message":{"role":"assistant","content":"!"},'
                    '"done":true}'
                )

        class _MockClient:
            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                pass

            def stream(self, *_args, **_kwargs):
                return _MockResp()

        monkeypatch.setattr(op_mod.httpx, "Client", lambda timeout: _MockClient())
        monkeypatch.setattr(
            op_mod, "get_available_models", lambda: ["gemma3:4b"]
        )

        provider = op_mod.OllamaProvider()
        chunks = list(
            provider.chat_stream(
                [LLMMessage(role="user", content="x")],
                model="gemma3:4b",
            )
        )
        assert chunks == ["Hallo ", "Welt", "!"]

    def test_stream_skips_non_json_frames(self, monkeypatch) -> None:
        from core.llm import ollama_provider as op_mod

        class _MockResp:
            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                pass

            def raise_for_status(self) -> None:
                pass

            def iter_lines(self):
                yield "kein-json"
                yield '{"message":{"content":"ok"},"done":true}'

        class _MockClient:
            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                pass

            def stream(self, *_args, **_kwargs):
                return _MockResp()

        monkeypatch.setattr(op_mod.httpx, "Client", lambda timeout: _MockClient())
        monkeypatch.setattr(
            op_mod, "get_available_models", lambda: ["gemma3:4b"]
        )
        provider = op_mod.OllamaProvider()
        chunks = list(
            provider.chat_stream(
                [LLMMessage(role="user", content="x")], model="gemma3:4b"
            )
        )
        assert chunks == ["ok"]

    def test_stream_returns_empty_when_no_model(self, monkeypatch) -> None:
        from core.llm import ollama_provider as op_mod

        monkeypatch.setattr(op_mod, "get_available_models", lambda: [])
        provider = op_mod.OllamaProvider()
        chunks = list(
            provider.chat_stream([LLMMessage(role="user", content="x")])
        )
        assert chunks == []

    def test_stream_handles_connect_error_gracefully(
        self, monkeypatch
    ) -> None:
        from core.llm import ollama_provider as op_mod

        def _raise(*args, **kwargs):
            raise op_mod.httpx.ConnectError("no server")

        class _MockClient:
            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                pass

            def stream(self, *args, **kwargs):
                _raise()

        monkeypatch.setattr(op_mod.httpx, "Client", lambda timeout: _MockClient())
        monkeypatch.setattr(
            op_mod, "get_available_models", lambda: ["gemma3:4b"]
        )
        provider = op_mod.OllamaProvider()
        # Kein Crash, leerer Iterator.
        chunks = list(
            provider.chat_stream(
                [LLMMessage(role="user", content="x")], model="gemma3:4b"
            )
        )
        assert chunks == []
