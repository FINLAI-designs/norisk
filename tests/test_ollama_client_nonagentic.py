"""
test_ollama_client_nonagentic — Invarianten-Test: Der Security-Chat bleibt
nicht-agentic (Plan P1-6).

Hintergrund: Die "nicht-agentic"-Eigenschaft (kein Tool-Calling, kein
WebFetch) ist KEINE Modell-Eigenschaft, sondern reine App-Konfiguration —
sie hält die "Lethal Trifecta" strukturell unvollständig (kein
Exfiltrationskanal). Verfügbare Modelle (gemma3, qwen3) sind tool-fähig;
würde der Chat versehentlich ein ``tools``-Array senden, kippte die gesamte
Sicherheitsbewertung still. Dieser Test sperrt die Invariante.

Author: Patrick Riederich
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from core.llm.ollama_client import OllamaClient


class _FakeStreamResponse:
    """Minimaler Kontextmanager-Ersatz für requests.post(stream=True)."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def __enter__(self) -> _FakeStreamResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def raise_for_status(self) -> None:
        pass

    def iter_lines(self) -> list[bytes]:
        # Eine vollständige, abgeschlossene Streaming-Antwort.
        chunk = {"message": {"content": "Antwort."}, "done": True}
        return [json.dumps(chunk).encode("utf-8")]


def test_chat_payload_enthaelt_kein_tools_array() -> None:
    captured: dict[str, Any] = {}

    def _fake_post(url: str, json: dict | None = None, **kwargs: Any):  # noqa: A002
        captured["url"] = url
        captured["payload"] = json
        return _FakeStreamResponse(json or {})

    with patch(
        "core.llm.ollama_client.requests.post", side_effect=_fake_post
    ):
        client = OllamaClient()
        out = client.chat(
            model="qwen3:8b",
            messages=[{"role": "user", "content": "Was ist Phishing?"}],
            on_token=lambda _t: None,
            system_prompt="System",
            temperature=0.3,
        )

    assert out == "Antwort."
    payload = captured["payload"]
    # KERN-Invariante: kein Tool-Calling.
    assert "tools" not in payload
    assert "tool_choice" not in payload
    # Streaming aktiv, Temperatur in options.
    assert payload["stream"] is True
    assert payload["options"]["temperature"] == 0.3
    # Modell warm halten (keep_alive ist ein Top-Level-Feld, nicht in options).
    assert payload["keep_alive"] == "30m"
    # Endpoint ist /api/chat (kein /api/pull|create|push).
    assert captured["url"].endswith("/api/chat")
