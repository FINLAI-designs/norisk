"""
test_ollama_utils_cache — Tests fuer den TTL-Cache in ``ollama_utils``.

Hintergrund: Security-Chat-Tool-Init machte 3 sequentielle HTTP-Calls
zum Ollama-Server (Health-Check + Modell-Liste 2x) im UI-Thread. Mit
TTL-Cache reicht **ein** Call beim Erst-Init, alle weiteren Aufrufe
in den naechsten 30 s kommen aus dem Cache.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core import ollama_utils


@pytest.fixture(autouse=True)
def _reset_caches():
    """Loescht Caches zwischen Tests — sonst leaken Werte ueber Tests."""
    ollama_utils.invalidate_ollama_caches()
    yield
    ollama_utils.invalidate_ollama_caches()


class TestIsOllamaRunningCache:
    def test_zweiter_call_kommt_aus_cache(self) -> None:
        with patch.object(ollama_utils, "requests") as mock_requests:
            mock_resp = MagicMock(status_code=200)
            mock_requests.get.return_value = mock_resp
            mock_requests.RequestException = Exception

            r1 = ollama_utils.is_ollama_running()
            r2 = ollama_utils.is_ollama_running()
            r3 = ollama_utils.is_ollama_running()

            assert r1 is r2 is r3 is True
            # HTTP-Call darf nur 1x stattfinden
            assert mock_requests.get.call_count == 1

    def test_cache_speichert_auch_negative_ergebnisse(self) -> None:
        """Wenn Ollama nicht laeuft, darf der Cache das auch fuer 30 s
        merken — sonst wuerde jeder UI-Aktion einen 2-s-Timeout
        aufaddieren."""
        with patch.object(ollama_utils, "requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.get.side_effect = mock_requests.RequestException()

            r1 = ollama_utils.is_ollama_running()
            r2 = ollama_utils.is_ollama_running()

            assert r1 is False and r2 is False
            assert mock_requests.get.call_count == 1

    def test_invalidate_cache_loescht_health(self) -> None:
        with patch.object(ollama_utils, "requests") as mock_requests:
            mock_resp = MagicMock(status_code=200)
            mock_requests.get.return_value = mock_resp
            mock_requests.RequestException = Exception

            ollama_utils.is_ollama_running()
            ollama_utils.invalidate_ollama_caches()
            ollama_utils.is_ollama_running()

            assert mock_requests.get.call_count == 2


class TestGetAvailableModelsCache:
    def test_zweiter_call_kommt_aus_cache(self) -> None:
        with patch.object(ollama_utils, "requests") as mock_requests:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {
                "models": [
                    {"name": "qwen3:8b"},
                    {"name": "gemma3:latest"},
                ]
            }
            mock_requests.get.return_value = mock_resp
            mock_requests.RequestException = Exception

            m1 = ollama_utils.get_available_models()
            m2 = ollama_utils.get_available_models()
            m3 = ollama_utils.get_available_models()

            assert m1 == m2 == m3 == ["qwen3:8b", "gemma3:latest"]
            assert mock_requests.get.call_count == 1

    def test_cache_liefert_defensive_kopie(self) -> None:
        """Caller darf das Ergebnis modifizieren, ohne den Cache zu vergiften."""
        with patch.object(ollama_utils, "requests") as mock_requests:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {"models": [{"name": "qwen3:8b"}]}
            mock_requests.get.return_value = mock_resp
            mock_requests.RequestException = Exception

            m1 = ollama_utils.get_available_models()
            m1.append("BAD")
            m2 = ollama_utils.get_available_models()

            assert m2 == ["qwen3:8b"]
            assert "BAD" not in m2

    def test_leeres_ergebnis_wird_auch_gecacht(self) -> None:
        """Wenn Ollama nicht antwortet, sollen wiederholte Calls nicht
        wieder 3 s ins Leere laufen."""
        with patch.object(ollama_utils, "requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.get.side_effect = mock_requests.RequestException()

            m1 = ollama_utils.get_available_models()
            m2 = ollama_utils.get_available_models()

            assert m1 == m2 == []
            assert mock_requests.get.call_count == 1


class TestInvalidateOllamaCaches:
    def test_invalidate_loescht_beide_caches(self) -> None:
        ollama_utils._HEALTH_CACHE = (0.0, True)
        ollama_utils._MODELS_CACHE = (0.0, ["x"])

        ollama_utils.invalidate_ollama_caches()

        assert ollama_utils._HEALTH_CACHE is None
        assert ollama_utils._MODELS_CACHE is None
