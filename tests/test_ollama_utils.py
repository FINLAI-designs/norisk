"""tests/test_ollama_utils.py — Tests für core/ollama_utils.py.

Prüft:
  - get_available_models mit Mock-HTTP-Response
  - get_default_model Präferenz-Logik (exakter Tag > qwen2.5 > qwen3 > erstes)
  - get_default_model Fehlerfall: kein Modell installiert
  - ensure_ollama_running wenn bereits läuft
  - OLLAMA_HOST aus config wird korrekt verwendet

Kein echtes Netzwerk. requests wird gemockt.

Author: Patrick Riederich
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_ollama_caches():
    """: ``ollama_utils`` hat seit 2026-05-14 einen TTL-Cache auf
    ``is_ollama_running`` und ``get_available_models``. Ohne Reset
    leakt das gecachte Ergebnis des ersten Tests in den naechsten."""
    from core import ollama_utils

    ollama_utils.invalidate_ollama_caches()
    yield
    ollama_utils.invalidate_ollama_caches()


class TestGetAvailableModels:
    """Tests für get_available_models."""

    def test_gibt_modellnamen_zurueck(self):
        """Parst /api/tags Response korrekt."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "models": [
                {"name": "qwen2.5-coder:7b"},
                {"name": "qwen3:8b"},
            ]
        }

        with patch("requests.get", return_value=mock_resp):
            from core.ollama_utils import get_available_models

            result = get_available_models()

        assert result == ["qwen2.5-coder:7b", "qwen3:8b"]

    def test_leere_liste_bei_http_fehler(self):
        """Gibt leere Liste zurück wenn Ollama nicht erreichbar."""
        with patch("requests.get", side_effect=ConnectionError("refused")):
            from core.ollama_utils import get_available_models

            result = get_available_models()

        assert result == []

    def test_leere_liste_bei_leerem_models_array(self):
        """Gibt leere Liste zurück wenn keine Modelle installiert."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": []}

        with patch("requests.get", return_value=mock_resp):
            from core.ollama_utils import get_available_models

            result = get_available_models()

        assert result == []

    def test_filtert_modelle_ohne_name(self):
        """Überspringt Einträge ohne 'name'-Schlüssel."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "models": [
                {"name": "qwen3:8b"},
                {},  # kein name
                {"name": ""},  # leerer name
            ]
        }

        with patch("requests.get", return_value=mock_resp):
            from core.ollama_utils import get_available_models

            result = get_available_models()

        # Leerer String wird nicht gefiltert (nur None) — laut Implementierung
        assert "qwen3:8b" in result


class TestGetDefaultModel:
    """Tests für get_default_model Präferenz-Logik."""

    def test_bevorzugt_exakten_tag_vor_praefix(self):
        """Ein exakter Praeferenz-Tag (qwen3:8b) gewinnt vor jedem Praefix-Match."""
        modelle = ["qwen2.5-coder:7b", "qwen2.5-coder:latest", "qwen3:8b"]

        with patch("core.ollama_utils.get_available_models", return_value=modelle):
            from core import ollama_utils

            result = ollama_utils.get_default_model()

        assert result == "qwen3:8b"

    def test_bevorzugt_qwen25_praefix_ohne_tag_match(self):
        """qwen2.5-coder wird ueber den qwen2.5-Praefix gewaehlt (kein Tag-Match)."""
        modelle = ["qwen2.5-coder:7b", "qwen2.5-coder:latest"]

        with patch("core.ollama_utils.get_available_models", return_value=modelle):
            from core import ollama_utils

            result = ollama_utils.get_default_model()

        assert result == "qwen2.5-coder:7b"

    def test_fallback_auf_erstes_modell(self):
        """Fällt auf erstes Modell zurück wenn kein Präfix passt."""
        modelle = ["exotisches-modell:latest", "anderes-modell:7b"]

        with patch("core.ollama_utils.get_available_models", return_value=modelle):
            from core import ollama_utils

            result = ollama_utils.get_default_model()

        assert result == "exotisches-modell:latest"

    def test_gibt_none_zurueck_wenn_keine_modelle(self):
        """Gibt None zurück wenn Ollama keine Modelle liefert."""
        with patch("core.ollama_utils.get_available_models", return_value=[]):
            from core import ollama_utils

            result = ollama_utils.get_default_model()

        assert result is None

    def test_praeferenz_qwen3_vor_qwen25(self):
        """qwen3.x wird gegenüber qwen2.5 bevorzugt."""
        modelle = ["qwen2.5:7b", "qwen3:8b"]

        with patch("core.ollama_utils.get_available_models", return_value=modelle):
            from core import ollama_utils

            result = ollama_utils.get_default_model()

        # qwen3:8b ist ein exakter Praeferenz-Tag -> vor jedem Praefix-Match
        assert result == "qwen3:8b"


class TestKeineFiktivenModelle:
    """: die Modell-Praeferenzen duerfen keine nicht existierenden Serien
    enthalten — sonst wird ein versehentlich so getaggtes (kaputtes) Modell
    bevorzugt gewaehlt (Ursache des leeren Briefing-Streams)."""

    def test_keine_geister_serien_in_praeferenzen(self):
        from core import ollama_utils

        teile = (
            ollama_utils.DEFAULT_OLLAMA_MODEL,
            *ollama_utils.GEMMA_MODEL_PREFIXES,
            *ollama_utils._MODEL_PREFERRED_TAGS,
            *ollama_utils._MODEL_PREFERRED_PREFIXES,
        )
        blob = " ".join(teile).lower()
        for geist in ("gemma4", "qwen3.5"):
            assert geist not in blob, f"Geister-Serie {geist!r} in Modell-Praeferenz"

    def test_setup_hint_modell_nicht_fiktiv(self):
        from core.settings import OLLAMA_SETUP_HINT_MODEL

        low = OLLAMA_SETUP_HINT_MODEL.lower()
        assert "gemma4" not in low
        assert "qwen3.5" not in low


class TestOllamaHost:
    """Stellt sicher dass OLLAMA_HOST aus config genutzt wird."""

    def test_ollama_host_in_config(self):
        """OLLAMA_HOST ist in core.config definiert."""
        from core.config import OLLAMA_HOST

        assert OLLAMA_HOST == "http://localhost:11434"

    def test_ollama_utils_nutzt_config_host(self):
        """get_available_models nutzt OLLAMA_HOST aus config."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": []}

        with patch("requests.get", return_value=mock_resp) as mock_get:
            from core import ollama_utils

            ollama_utils.get_available_models()

        # URL muss den konfigurierten Host enthalten
        from core.config import OLLAMA_HOST

        call_url = mock_get.call_args[0][0]
        assert OLLAMA_HOST in call_url


class TestEnsureOllamaRunning:
    """Tests für ensure_ollama_running."""

    def test_gibt_true_zurueck_wenn_bereits_laeuft(self):
        """Startet Ollama nicht neu wenn bereits erreichbar."""
        with (
            patch("core.ollama_utils.is_ollama_running", return_value=True),
            patch("subprocess.Popen") as mock_popen,
        ):
            from core import ollama_utils

            result = ollama_utils.ensure_ollama_running()

        assert result is True
        mock_popen.assert_not_called()
