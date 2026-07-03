"""
test_assistant_tab — GUI-Smoke des Inline-FINLAI-Assistenten, C).

Deterministisch (ohne Ollama). Treibt die Render-/Worker-Logik direkt; der
sicherheitsrelevante Vertrag „angezeigter Endtext = GEFILTERTE Antwort" wird über
die synchrone Finalize-Ersetzung geprüft. Zwei qtbot-Läufe runden den echten
QThread-Pfad (Streaming + No-Service) ab.

Author: Patrick Riederich
"""

from __future__ import annotations

import pytest

from core.assistant.rag_service import RetrievedSource
from core.assistant.unified_assistant_service import AssistantResponse
from core.guardrails.guardrails import DOMAIN_HANDBOOK, DOMAIN_SECURITY
from core.help.tabs.assistant_tab import (
    _NO_SERVICE_MSG,
    AssistantTab,
    _AssistantWorker,
)

pytestmark = pytest.mark.gui


class _FakeService:
    """Synchroner Service-Stub: streamt Roh-Token, liefert gefilterte Antwort."""

    def __init__(self, answer: str = "Gefilterte Antwort.", sources=None) -> None:
        self.model = "m"
        self._answer = answer
        self._sources = sources or []
        self.reset_called = 0

    def ask(self, content, on_token):  # noqa: ANN001, D102
        on_token("ROH ")
        on_token("tokens")
        return AssistantResponse(
            answer=self._answer, domain=DOMAIN_HANDBOOK, sources=self._sources
        )

    def reset(self) -> None:
        self.reset_called += 1


def _tab(qtbot, provider=None) -> AssistantTab:
    tab = AssistantTab(service_provider=provider)
    qtbot.addWidget(tab)
    return tab


# ─────────────────────────────────────────────────────────────────────────────
# Aufbau + Render-Logik (synchron)
# ─────────────────────────────────────────────────────────────────────────────
def test_construct_shows_greeting_no_sources(qtbot, app):
    # isHidden spiegelt das explizite setVisible-Flag (unabhängig davon, ob das
    # Top-Level gezeigt wurde) — robuster als isVisible im headless-Test.
    tab = _tab(qtbot)
    assert "FINLAI" in tab._transcript.toPlainText()
    assert tab._sources.isHidden()
    assert not tab._send_btn.isHidden()
    assert tab._stop_btn.isHidden()


def test_finalize_replaces_raw_with_filtered(qtbot, app):
    tab = _tab(qtbot)
    tab._append_user("Frage?")
    tab._begin_answer()
    tab._on_token("rohes ")
    tab._on_token("Leak")
    tab._on_done(AssistantResponse(answer="GEPRÜFT", domain=DOMAIN_HANDBOOK))
    text = tab._transcript.toPlainText()
    assert "GEPRÜFT" in text
    assert "rohes Leak" not in text  # Roh-Stream wurde durch Endfassung ersetzt


def test_render_sources_grouped(qtbot, app):
    tab = _tab(qtbot)
    srcs = [
        RetrievedSource(DOMAIN_HANDBOOK, "Export", "x", 0.4, "ANWENDER.md"),
        RetrievedSource(DOMAIN_SECURITY, "OWASP", "y", 0.3, "owasp.md"),
    ]
    tab._render_sources(srcs)
    assert not tab._sources.isHidden()
    htmltext = tab._sources.toHtml()
    assert "Handbuch" in htmltext and "Sicherheit" in htmltext
    assert "Export" in htmltext and "OWASP" in htmltext
    tab._render_sources([])  # leere Quellen verstecken das Panel
    assert tab._sources.isHidden()


def test_failed_path_shows_message(qtbot, app):
    tab = _tab(qtbot)
    tab._append_user("Frage?")
    tab._begin_answer()
    tab._on_failed("Fehlertext XY")
    assert "Fehlertext XY" in tab._transcript.toPlainText()


def test_cleanup_safe_without_worker(qtbot, app):
    tab = _tab(qtbot)
    tab.cleanup()  # darf nicht crashen
    tab.cleanup()  # idempotent


# ─────────────────────────────────────────────────────────────────────────────
# Worker-Pfad (echter QThread, via qtbot deterministisch)
# ─────────────────────────────────────────────────────────────────────────────
def test_worker_no_service_emits_failed(qtbot, app):
    worker = _AssistantWorker(provider=None, content="x")
    with qtbot.waitSignal(worker.failed, timeout=2000) as blocker:
        worker.start()
    assert blocker.args[0] == _NO_SERVICE_MSG
    worker.wait()


def test_worker_streams_and_completes(qtbot, app):
    svc = _FakeService(answer="Endfassung")
    tokens: list[str] = []
    worker = _AssistantWorker(provider=lambda: svc, content="frage")
    worker.token.connect(tokens.append)
    with qtbot.waitSignal(worker.done, timeout=2000) as blocker:
        worker.start()
    worker.wait()
    assert "".join(tokens) == "ROH tokens"
    assert blocker.args[0].answer == "Endfassung"


def test_send_end_to_end_through_thread(qtbot, app):
    svc = _FakeService(
        answer="Fertige Antwort",
        sources=[RetrievedSource(DOMAIN_HANDBOOK, "H", "x", 0.5, "h.md")],
    )
    tab = _tab(qtbot, provider=lambda: svc)
    tab._input.setText("Wie exportiere ich?")
    tab._on_send()
    # Auf Worker-Abschluss warten: _on_finished setzt _worker zurück auf None.
    qtbot.waitUntil(lambda: tab._worker is None, timeout=3000)
    text = tab._transcript.toPlainText()
    assert "Fertige Antwort" in text
    assert not tab._sources.isHidden()
