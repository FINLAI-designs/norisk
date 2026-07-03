"""Tests fuer core/sbom_aibom/ai_bom_service.py.

Prueft die Aggregation lokaler Ollama-Modelle (via Mock-Response). Seit
aibom listet NoRisk keine Cloud-KI-Provider mehr —
selbst Bestandsdaten-API-Keys in SecureStorage werden nicht in die AI-BOM
aufgenommen. Die Tests touchen weder Netzwerk noch echte Storage — alle
externen Quellen werden via monkeypatch ersetzt.

-aibom.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from core.sbom_aibom import ai_bom_service
from core.sbom_aibom.ai_bom_service import AiBomService, build_ai_bom


def _fake_response(payload: dict | list, status: int = 200) -> SimpleNamespace:
    """Hilfs-Konstruktor fuer requests-aehnliche Antwortobjekte.

    Args:
        payload: JSON-Body, der von ``response.json`` zurueckgegeben wird.
        status: HTTP-Statuscode.

    Returns:
        Namespace mit ``status_code`` und ``json``.
    """
    return SimpleNamespace(status_code=status, json=lambda: payload)


def _patch_ollama(monkeypatch, models: list[dict] | None) -> None:
    """Ersetzt den ``requests.get`` im AI-BOM-Modul durch ein Stub.

    Args:
        monkeypatch: pytest-Fixture.
        models: Modelliste fuer ``/api/tags`` oder ``None`` fuer Fehler-Fall.
    """

    def _stub(_url, timeout=None):  # noqa: ARG001
        if models is None:
            msg = "ollama nicht erreichbar"
            raise ai_bom_service.requests.RequestException(msg)
        return _fake_response({"models": models})

    monkeypatch.setattr(ai_bom_service.requests, "get", _stub)


def _patch_storage(monkeypatch, configured_keys: set[str]) -> None:
    """Ersetzt ``get_secure_storage`` durch ein Stub mit definierten Keys.

    Args:
        monkeypatch: pytest-Fixture.
        configured_keys: Menge der SecureStorage-Keys, die einen Wert haben.
    """

    class _Storage:
        def get(self, key: str) -> str | None:
            return "stub-key-value" if key in configured_keys else None

    monkeypatch.setattr(
        "core.security.encryption.get_secure_storage",
        lambda: _Storage(),
    )


def test_build_ai_bom_ohne_ollama_und_keys(monkeypatch):
    """Ohne Ollama und ohne API-Keys ist die AI-BOM leer."""
    _patch_ollama(monkeypatch, models=None)
    _patch_storage(monkeypatch, configured_keys=set())

    components = build_ai_bom()

    assert components == []


def test_build_ai_bom_mit_ollama_modellen(monkeypatch):
    """Installierte Ollama-Modelle werden als lokale Komponenten aufgenommen."""
    _patch_ollama(
        monkeypatch,
        models=[
            {"name": "qwen3:8b", "digest": "abc123", "size": 5_000_000_000},
            {"name": "gemma2:9b", "digest": "def456", "size": 6_000_000_000},
            {"name": ""},  # Defekter Eintrag, muss ignoriert werden.
        ],
    )
    _patch_storage(monkeypatch, configured_keys=set())

    components = build_ai_bom()

    assert len(components) == 2
    assert {c.name for c in components} == {"qwen3:8b", "gemma2:9b"}
    for component in components:
        assert component.kind == "model"
        assert component.location == "local"
        assert component.digest
        assert component.size_bytes > 0


def test_build_ai_bom_ignoriert_bestandsdaten_cloud_keys(monkeypatch):
    """Bestandsdaten-API-Keys (DeepL/OpenAI/Anthropic) tauchen nicht mehr auf.

    aibom: Cloud-Provider sind aus NoRisk entfernt.
    Auch wenn ein Anwender frueher Keys in SecureStorage abgelegt hat,
    darf die AI-BOM sie NICHT mehr als aktive KI-Komponenten auflisten —
    die AI-BOM dokumentiert nur tatsaechlich genutzte KI.
    """
    _patch_ollama(monkeypatch, models=[])
    _patch_storage(
        monkeypatch,
        configured_keys={"deepl_api_key", "anthropic_api_key", "openai_api_key"},
    )

    components = build_ai_bom()

    assert components == []


def test_build_ai_bom_sortierung_alphabetisch(monkeypatch):
    """Lokale Modelle werden alphabetisch sortiert."""
    _patch_ollama(
        monkeypatch,
        models=[
            {"name": "zeta-model", "digest": "z", "size": 1},
            {"name": "alpha-model", "digest": "a", "size": 1},
        ],
    )
    _patch_storage(monkeypatch, configured_keys=set())

    components = build_ai_bom()

    assert [c.name for c in components] == ["alpha-model", "zeta-model"]


def test_ai_bom_service_generate_top_level_fields(monkeypatch):
    """Das exportierte AI-BOM-Dokument hat die erwarteten Top-Level-Felder."""
    _patch_ollama(
        monkeypatch,
        models=[{"name": "qwen3:8b", "digest": "abc", "size": 1}],
    )
    _patch_storage(monkeypatch, configured_keys=set())

    document = AiBomService().generate()

    assert document["aibomFormat"] == "FINLAI-AIBOM"
    assert document["specVersion"] == "0.1"
    assert document["generatedAt"].endswith("Z")
    assert document["application"]["name"] == "NoRisk by FINLAI"
    components = document["components"]
    assert isinstance(components, list)
    assert len(components) == 1
    # Jede Komponente muss als Dict mit den Pflichtfeldern serialisiert sein.
    for component in components:
        assert {
            "name",
            "kind",
            "location",
            "purpose",
            "data_flow",
        }.issubset(component.keys())


def test_ai_bom_service_export_json(monkeypatch, tmp_path):
    """Der JSON-Export schreibt ein parsbares Dokument an den Zielpfad."""
    _patch_ollama(monkeypatch, models=[])
    _patch_storage(monkeypatch, configured_keys=set())

    service = AiBomService()
    document = service.generate()
    target = tmp_path / "nested" / "ai_bom.json"

    written = service.export_json(document, target)

    assert written == target
    parsed = json.loads(target.read_text(encoding="utf-8"))
    assert parsed["aibomFormat"] == "FINLAI-AIBOM"
    assert parsed["components"] == []
