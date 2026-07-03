"""
test_handbuch_gui — Tests für Handbuch-Assistent Etappe 2 (GUI + Service).

Prüft:
    - HandbuchService.ask: Gibt Antwort mit Quellen zurück (mit Mock-LLM)
    - HandbuchService.ask: Kein Absturz wenn nicht initialisiert (__new__)
    - HandbuchService.ask: Rollenaliase "user" und "admin" werden aufgelöst
    - HandbuchService.rebuild: Kein Absturz, Index wird neu gebaut
    - HandbuchService.ask: Admin-Rolle lädt mehr Chunks als User-Rolle

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.handbuch_assistent.application.document_loader import DocumentLoader
from tools.handbuch_assistent.application.handbuch_service import HandbuchService
from tools.handbuch_assistent.domain.models import HandbuchAnswer

# Cleanup-Sprint 2026-04-29: scikit-learn ist optional. Tests, die auf
# einen funktionierenden TF-IDF-Index angewiesen sind (Service.ask mit
# Doc-Chunks, HelpWorker mit echtem Service), werden ohne sklearn
# uebersprungen.
_SKLEARN_REASON = (
    "scikit-learn ist optional (TF-IDF/Cosine im ChunkIndexer). "
    "Service.ask liefert ohne Index keine Treffer."
)
try:
    import sklearn  # noqa: F401 -- nur zur Verfuegbarkeits-Pruefung

    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

#: Liste aller in einem Test ueber:func:`_make_mock_service` erzeugten
#: Service-Instanzen. Der autouse-``_cleanup_handbuch_services``-Fixture
#: ruft am Test-Ende ``shutdown`` auf jedem Eintrag, damit der
#: watchdog-Observer-Thread + Pending-Debounce-Timer nicht ueber das
#: Test-Ende hinaus weiterlaufen (Linux-Smoke-CI scheiterte sonst
#: mit Exit 134 + ``ValueError: I/O operation on closed file``).
_created_services: list[HandbuchService] = []


@pytest.fixture(autouse=True)
def _cleanup_handbuch_services():
    """Stoppt alle in diesem Test erzeugten HandbuchService-Instanzen."""
    yield
    while _created_services:
        svc = _created_services.pop()
        try:
            svc.shutdown()
        except Exception:  # noqa: BLE001 -- Cleanup darf nicht scheitern
            pass


@pytest.fixture
def docs_dir(tmp_path: Path) -> Path:
    """Erstellt ein temporäres docs-Verzeichnis mit Testdateien."""
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "ANWENDERHANDBUCH.md").write_text(
        "## Saldenliste importieren\n\n"
        "Um eine Saldenliste zu importieren:\n\n"
        "1. Klicke auf Buchprüfung in der Sidebar\n"
        "2. Wähle Datei importieren\n"
        "3. Wähle deine Excel-Datei\n",
        encoding="utf-8",
    )
    (docs / "ENTWICKLERHANDBUCH.md").write_text(
        "## Architektur\n\n"
        "FINLAI verwendet hexagonale Architektur mit drei Schichten: "
        "Domain, Application und Adapter. Jede Schicht hat klare Grenzen "
        "und Abhängigkeitsregeln.\n\n"
        "## Tests\n\n"
        "Alle Tests laufen ohne GUI via pytest. Die Domain-Schicht hat "
        "keine externen Abhängigkeiten und ist vollständig testbar.",
        encoding="utf-8",
    )
    (docs / "BASISINFO.md").write_text(
        "## Allgemeine Information\n\n"
        "FINLAI ist eine lokale Desktop-Anwendung für Steuerberatung. "
        "Alle Daten werden verschlüsselt lokal gespeichert.",
        encoding="utf-8",
    )
    return docs


def _make_mock_service(
    docs: Path,
    answer_text: str = "Test-Antwort.",
    role: str = "all",
) -> HandbuchService:
    """Erstellt einen HandbuchService mit gemocktem OllamaClient.

    Args:
        docs: Pfad zum docs-Verzeichnis.
        answer_text: Text den der Mock-Client als Antwort zurückgibt.
        role: Rolle für die Initialisierung und spätere ask-Aufrufe.

    Returns:
        Initialisierter HandbuchService mit Mock-LLM.
    """
    from tools.handbuch_assistent.application.rag_retriever import RagRetriever

    mock_client = MagicMock()

    def mock_chat(model, messages, on_token, system_prompt="", temperature=0.7):
        on_token(answer_text)
        return answer_text

    mock_client.chat.side_effect = mock_chat

    svc = HandbuchService(docs_path=docs)

    # _setup_retriever patchen damit kein echter OllamaClient entsteht
    with patch.object(svc, "_setup_retriever"):
        svc.initialize(role=role)

    # Retriever mit Mock-Client einrichten
    svc._retriever = RagRetriever(
        indexer=svc._indexer,
        client=mock_client,
        model="llama3.2",
    )
    # _current_role setzen damit ask nicht neu initialisiert
    svc._current_role = role

    # Fuer den autouse-Cleanup-Fixture vermerken.
    _created_services.append(svc)
    return svc


# ---------------------------------------------------------------------------
# HandbuchService — Funktionale Tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _SKLEARN_AVAILABLE, reason=_SKLEARN_REASON)
class TestHandbuchServiceMitDocs:
    """Tests für HandbuchService mit echten Docs und Mock-LLM."""

    def test_ask_gibt_antwort_mit_quellen(self, docs_dir: Path) -> None:
        """ask gibt HandbuchAnswer mit nicht-leerem answer und sources zurück."""
        svc = _make_mock_service(
            docs_dir, answer_text="Das ist die Antwort.", role="anwender"
        )
        answer = svc.ask("Wie importiere ich eine Saldenliste?", role="anwender")
        assert isinstance(answer, HandbuchAnswer)
        assert answer.answer != ""
        assert len(answer.sources) > 0

    def test_ask_user_rolle_alias(self, docs_dir: Path) -> None:
        """ask löst Alias 'user' → 'anwender' korrekt auf; kein Absturz."""
        svc = _make_mock_service(docs_dir, role="anwender")
        # "user" wird zu "anwender" gemappt — gleiche Rolle, kein Re-Init
        answer = svc.ask("Saldenliste importieren?", role="user")
        assert isinstance(answer, HandbuchAnswer)

    def test_ask_admin_rolle_alias(self, docs_dir: Path) -> None:
        """ask löst Alias 'admin' → 'all' korrekt auf; kein Absturz."""
        svc = _make_mock_service(docs_dir, role="all")
        answer = svc.ask("Architektur?", role="admin")
        assert isinstance(answer, HandbuchAnswer)

    def test_rebuild_kein_absturz(self, docs_dir: Path) -> None:
        """rebuild läuft ohne Fehler durch und baut den Index neu auf."""
        svc = _make_mock_service(docs_dir)
        old_count = svc.chunk_count
        svc.rebuild()
        assert svc.chunk_count == old_count  # gleiche Anzahl nach Neuaufbau

    def test_admin_mehr_chunks_als_anwender(self, docs_dir: Path) -> None:
        """Admin-Index enthält mehr Chunks als Anwender-Index."""
        loader_user = DocumentLoader(docs_dir)
        loader_admin = DocumentLoader(docs_dir)

        chunks_user = loader_user.load_for_role("anwender")
        chunks_admin = loader_admin.load_for_role("all")

        # Admin (all) lädt auch Entwicklerhandbuch → mehr Chunks
        assert len(chunks_admin) >= len(chunks_user)

    def test_ask_erfolgreich_success_true(self, docs_dir: Path) -> None:
        """ask liefert success=True bei korrekter Antwort."""
        svc = _make_mock_service(
            docs_dir, answer_text="Antwort erfolgreich.", role="anwender"
        )
        answer = svc.ask("Wie importiere ich eine Saldenliste?", role="anwender")
        assert answer.success is True


# ---------------------------------------------------------------------------
# HandbuchService — Robustheit
# ---------------------------------------------------------------------------


class TestHandbuchServiceRobustheit:
    """Tests für Robustheit des HandbuchService."""

    def test_ask_ohne_init_kein_absturz(self) -> None:
        """ask ohne vorherige Initialisierung kein Absturz."""
        svc = HandbuchService.__new__(HandbuchService)
        # Nur minimale Attribute setzen (wie der Spec-Test)
        svc._retriever = None  # type: ignore[attr-defined]
        # Kein Absturz erwartet — HandbuchService hat defensive getattr-Prüfungen
        answer = svc.ask("Wie importiere ich?", "user")
        assert answer is not None
        assert isinstance(answer, HandbuchAnswer)

    def test_shutdown_nach_nicht_initialisierten_service(self) -> None:
        """shutdown auf nicht-initialisiertem Service kein Absturz."""
        svc = HandbuchService()
        svc.shutdown()  # kein Fehler

    def test_rebuild_nach_shutdown_kein_absturz(self, docs_dir: Path) -> None:
        """rebuild nach shutdown kein Absturz."""
        svc = _make_mock_service(docs_dir)
        svc.shutdown()
        svc.rebuild()  # kein Fehler
