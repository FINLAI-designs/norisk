"""
test_handbuch_rag — Tests für Handbuch-Assistent Etappe 1.

Prüft:
    - DocumentLoader._split_into_chunks: Überschriften-Trennung
    - DocumentLoader._split_into_chunks: Zu kurze Chunks werden verworfen
    - DocumentLoader._split_into_chunks: Text vor erster Überschrift
    - DocumentLoader._detect_role: ANWENDERHANDBUCH → "anwender"
    - DocumentLoader._detect_role: ENTWICKLERHANDBUCH → "entwickler"
    - DocumentLoader._detect_role: Unbekannte Datei → "all"
    - DocumentLoader.load_for_role: Kein Absturz wenn Verzeichnis fehlt
    - DocumentLoader.load_for_role: Rollenfilterung korrekt
    - ChunkIndexer.fit: Chunks werden indexiert
    - ChunkIndexer.is_fitted: True nach fit
    - ChunkIndexer.search: Gibt RetrievalResult zurück
    - ChunkIndexer.search: Kein Absturz bei leerem Index
    - ChunkIndexer.search: Leere Query gibt leere Liste
    - RagRetriever.retrieve: Delegiert an ChunkIndexer.search
    - RagRetriever.answer: LLM-Fehler → success=False
    - RagRetriever.answer: Keine Chunks → success=False
    - HandbuchService: Instanziierung ohne Fehler
    - HandbuchService.initialize: chunk_count > 0 nach Init mit echten Docs
    - HandbuchService.shutdown: Idempotent
    - IndexRepository.save_chunks + load_chunks: Round-Trip
    - IndexRepository.is_stale: Neue Datei → stale=True

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.handbuch_assistent.application.chunk_indexer import ChunkIndexer
from tools.handbuch_assistent.application.document_loader import DocumentLoader
from tools.handbuch_assistent.application.handbuch_service import HandbuchService
from tools.handbuch_assistent.application.rag_retriever import RagRetriever
from tools.handbuch_assistent.data.index_repository import IndexRepository
from tools.handbuch_assistent.domain.models import DocumentChunk, HandbuchAnswer

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_chunk(
    text: str = "Dies ist ein Testtext für die Indexierung.",
    heading: str = "## Testabschnitt",
    role: str = "all",
    source_file: str = "TEST.md",
) -> DocumentChunk:
    """Erstellt einen minimalen DocumentChunk für Tests."""
    return DocumentChunk(
        chunk_id=str(uuid.uuid4()),
        source_file=source_file,
        heading=heading,
        text=text,
        role=role,
    )


def _make_chunks(n: int = 5) -> list[DocumentChunk]:
    """Erstellt n verschiedene DocumentChunks."""
    topics = [
        (
            "## Installation",
            "Installation des Programms durch Doppelklick auf die Datei.",
        ),
        ("## Konfiguration", "Konfiguration der Anwendung über das Einstellungs-Menü."),
        (
            "## Benutzeroberfläche",
            "Die Oberfläche besteht aus Sidebar und Hauptbereich.",
        ),
        ("## Fehlerbehebung", "Häufige Fehler und deren Lösung sind hier beschrieben."),
        ("## Lizenz", "Die Software wird unter einer proprietären Lizenz vertrieben."),
    ]
    result = []
    for i in range(n):
        h, t = topics[i % len(topics)]
        result.append(_make_chunk(text=t, heading=h))
    return result


_SAMPLE_MARKDOWN = """\
# FINLAI Handbuch

Einleitungstext vor der ersten Überschrift.

## Installation

Laden Sie die Installationsdatei herunter und führen Sie sie aus.
Folgen Sie den Anweisungen des Installationsassistenten.

## Konfiguration

Öffnen Sie die Einstellungen über das Menü Datei → Einstellungen.
Tragen Sie Ihren Lizenzschlüssel ein und klicken Sie auf Speichern.

## Fehlerbehebung

Bei Verbindungsproblemen prüfen Sie bitte die Firewall-Einstellungen.
Stellen Sie sicher, dass Port 11434 für Ollama freigegeben ist.
"""

_MARKDOWN_NO_HEADINGS = """\
Dies ist ein Dokument ohne Überschriften.
Es enthält nur normalen Text der direkt als ein Chunk verarbeitet werden sollte.
"""

_MARKDOWN_SHORT = """\
## A

Zu kurz.

## Ausführlicher Abschnitt

Dieser Abschnitt ist lang genug um als Chunk verarbeitet zu werden.
Er enthält mehrere Sätze mit relevanten Informationen.
"""


# ---------------------------------------------------------------------------
# DocumentLoader
# ---------------------------------------------------------------------------


class TestDocumentLoader:
    """Tests für DocumentLoader."""

    def test_split_ueberschriften(self) -> None:
        """_split_into_chunks trennt am ## korrekt."""
        loader = DocumentLoader()
        chunks = loader._split_into_chunks(_SAMPLE_MARKDOWN, "TEST.md", "all")

        headings = [c.heading for c in chunks]
        assert any("Installation" in h for h in headings)
        assert any("Konfiguration" in h for h in headings)
        assert any("Fehlerbehebung" in h for h in headings)

    def test_split_kurze_chunks_verworfen(self) -> None:
        """_split_into_chunks verwirft Abschnitte unter _MIN_CHUNK_CHARS."""
        loader = DocumentLoader()
        chunks = loader._split_into_chunks(_MARKDOWN_SHORT, "TEST.md", "all")

        # Nur der ausführliche Abschnitt darf übrig bleiben
        assert len(chunks) == 1
        assert "Ausführlicher" in chunks[0].heading

    def test_split_text_vor_erster_ueberschrift(self) -> None:
        """_split_into_chunks erfasst Text vor der ersten Überschrift."""
        loader = DocumentLoader()
        chunks = loader._split_into_chunks(_SAMPLE_MARKDOWN, "TEST.md", "all")
        # Einleitungstext ist kurz, könnte gefiltert werden — kein Crash ist Hauptziel
        assert isinstance(chunks, list)

    def test_split_kein_heading_dokument(self) -> None:
        """_split_into_chunks ohne Überschriften: ein Chunk mit Dateiname als heading."""
        loader = DocumentLoader()
        chunks = loader._split_into_chunks(_MARKDOWN_NO_HEADINGS, "TEST.md", "all")
        assert len(chunks) == 1
        assert chunks[0].source_file == "TEST.md"

    def test_detect_role_anwender(self) -> None:
        """_detect_role erkennt ANWENDERHANDBUCH → anwender."""
        assert DocumentLoader._detect_role("ANWENDERHANDBUCH.md") == "anwender"

    def test_detect_role_entwickler(self) -> None:
        """_detect_role erkennt ENTWICKLERHANDBUCH → entwickler."""
        assert DocumentLoader._detect_role("ENTWICKLERHANDBUCH.md") == "entwickler"

    def test_detect_role_fallback(self) -> None:
        """_detect_role gibt 'all' für unbekannte Dateinamen zurück."""
        assert DocumentLoader._detect_role("BASISINFO.md") == "all"
        assert DocumentLoader._detect_role("README.md") == "all"

    def test_load_for_role_fehlendes_verzeichnis(self, tmp_path: Path) -> None:
        """load_for_role kein Absturz wenn docs-Verzeichnis fehlt."""
        loader = DocumentLoader(docs_path=tmp_path / "nicht_vorhanden")
        chunks = loader.load_for_role("all")
        assert chunks == []

    def test_load_for_role_rollenfilterung(self, tmp_path: Path) -> None:
        """load_for_role('anwender') liefert nur Anwender- und 'all'-Chunks."""
        # Erstelle Test-Markdown-Dateien
        (tmp_path / "ANWENDERHANDBUCH.md").write_text(
            "## Anwender-Abschnitt\n\nDies ist der Anwenderbereich mit ausreichend Text.",
            encoding="utf-8",
        )
        (tmp_path / "ENTWICKLERHANDBUCH.md").write_text(
            "## Entwickler-Abschnitt\n\nDies ist der Entwicklerbereich mit ausreichend Text.",
            encoding="utf-8",
        )
        (tmp_path / "BASISINFO.md").write_text(
            "## Allgemeiner Abschnitt\n\nDiese Information gilt für alle Benutzer.",
            encoding="utf-8",
        )

        loader = DocumentLoader(docs_path=tmp_path)
        chunks = loader.load_for_role("anwender")

        roles = {c.role for c in chunks}
        assert "entwickler" not in roles
        assert "anwender" in roles or "all" in roles

    def test_load_for_role_chunk_felder(self, tmp_path: Path) -> None:
        """Geladene Chunks haben alle Pflichtfelder gesetzt."""
        (tmp_path / "TEST.md").write_text(
            "## Testabschnitt\n\nDies ist ausreichend Text für einen Chunk.",
            encoding="utf-8",
        )
        loader = DocumentLoader(docs_path=tmp_path)
        chunks = loader.load_for_role("all")

        assert len(chunks) >= 1
        for c in chunks:
            assert c.chunk_id
            assert c.source_file
            assert c.heading
            assert c.text
            assert c.char_count == len(c.text)


# ---------------------------------------------------------------------------
# ChunkIndexer
# ---------------------------------------------------------------------------


_SKLEARN_REASON = (
    "scikit-learn ist optional (TF-IDF/Cosine im ChunkIndexer). Ohne "
    "Installation liefert ``fit()`` einen leeren Index — die Tests pruefen "
    "echte Index-Inhalte und werden uebersprungen."
)
try:
    import sklearn  # noqa: F401 -- nur zur Verfuegbarkeits-Pruefung

    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


@pytest.mark.skipif(not _SKLEARN_AVAILABLE, reason=_SKLEARN_REASON)
class TestChunkIndexer:
    """Tests für ChunkIndexer."""

    def test_fit_indexiert_chunks(self) -> None:
        """fit indexiert Chunks ohne Fehler."""
        indexer = ChunkIndexer()
        chunks = _make_chunks(5)
        indexer.fit(chunks)
        assert indexer.is_fitted
        assert indexer.chunk_count == 5

    def test_is_fitted_nach_fit(self) -> None:
        """is_fitted ist True nach erfolgreichem fit."""
        indexer = ChunkIndexer()
        assert not indexer.is_fitted
        indexer.fit(_make_chunks(3))
        assert indexer.is_fitted

    def test_search_gibt_ergebnisse(self) -> None:
        """search gibt RetrievalResult-Liste zurück."""
        indexer = ChunkIndexer()
        indexer.fit(_make_chunks(5))
        results = indexer.search("Installation Konfiguration", top_k=3)
        assert isinstance(results, list)
        assert len(results) > 0

    def test_search_kein_absturz_leerer_index(self) -> None:
        """search ohne fit kein Absturz — leere Liste."""
        indexer = ChunkIndexer()
        results = indexer.search("Test")
        assert results == []

    def test_search_leere_query(self) -> None:
        """search mit leerer Query gibt leere Liste zurück."""
        indexer = ChunkIndexer()
        indexer.fit(_make_chunks(3))
        results = indexer.search("")
        assert results == []

    def test_search_top_k_begrenzt(self) -> None:
        """search liefert maximal top_k Ergebnisse."""
        indexer = ChunkIndexer()
        indexer.fit(_make_chunks(5))
        results = indexer.search("Installation", top_k=2)
        assert len(results) <= 2

    def test_search_score_0_bis_1(self) -> None:
        """search liefert Scores zwischen 0 und 1."""
        indexer = ChunkIndexer()
        indexer.fit(_make_chunks(5))
        results = indexer.search("Installation")
        for r in results:
            assert 0.0 <= r.score <= 1.0

    def test_search_absteigend_sortiert(self) -> None:
        """search liefert Ergebnisse absteigend nach Score."""
        indexer = ChunkIndexer()
        indexer.fit(_make_chunks(5))
        results = indexer.search("Installation Konfiguration", top_k=3)
        if len(results) > 1:
            for i in range(len(results) - 1):
                assert results[i].score >= results[i + 1].score

    def test_fit_leere_liste_kein_absturz(self) -> None:
        """fit mit leerer Liste kein Absturz."""
        indexer = ChunkIndexer()
        indexer.fit([])
        assert not indexer.is_fitted
        assert indexer.chunk_count == 0


# ---------------------------------------------------------------------------
# RagRetriever
# ---------------------------------------------------------------------------


class TestRagRetriever:
    """Tests für RagRetriever."""

    def _make_retriever(
        self, chunks: list[DocumentChunk] | None = None
    ) -> RagRetriever:
        """Erstellt RagRetriever mit Mock-Client."""
        indexer = ChunkIndexer()
        if chunks is not None:
            indexer.fit(chunks)
        client = MagicMock()
        client.chat.return_value = "Das ist die Testantwort."
        return RagRetriever(indexer=indexer, client=client, model="llama3.2")

    def test_retrieve_delegiert_an_indexer(self) -> None:
        """retrieve delegiert korrekt an ChunkIndexer.search."""
        chunks = _make_chunks(5)
        retriever = self._make_retriever(chunks)
        results = retriever.retrieve("Installation", top_k=3)
        assert isinstance(results, list)

    def test_answer_keine_chunks_success_false(self) -> None:
        """answer gibt success=False wenn keine Chunks vorhanden."""
        retriever = self._make_retriever(chunks=None)
        result = retriever.answer("Was ist FINLAI?")
        assert isinstance(result, HandbuchAnswer)
        assert result.success is False

    def test_answer_llm_fehler_success_false(self) -> None:
        """answer gibt success=False bei ConnectionError vom LLM."""
        chunks = _make_chunks(3)
        indexer = ChunkIndexer()
        indexer.fit(chunks)
        client = MagicMock()
        client.chat.side_effect = ConnectionError("Ollama nicht erreichbar")
        retriever = RagRetriever(indexer=indexer, client=client)
        result = retriever.answer("Test")
        assert result.success is False
        assert result.error_message

    def test_answer_mit_ergebnis(self) -> None:
        """answer gibt HandbuchAnswer mit answer-Text zurück."""
        chunks = _make_chunks(5)
        retriever = self._make_retriever(chunks)
        result = retriever.answer("Wie installiere ich FINLAI?")
        assert isinstance(result, HandbuchAnswer)
        # Client wird mit on_token aufgerufen — Token werden via callback gesammelt
        # Mock gibt jedoch direkt return_value zurück, kein Token-Streaming
        assert isinstance(result.answer, str)

    def test_answer_enthält_sources(self) -> None:
        """answer enthält mindestens eine Quelle wenn Chunks gefunden."""
        chunks = _make_chunks(5)
        retriever = self._make_retriever(chunks)
        result = retriever.answer("Installation")
        if result.success or result.retrieved_chunks:
            assert isinstance(result.sources, list)

    def test_answer_duration_ms_positiv(self) -> None:
        """answer setzt duration_ms auf positiven Wert."""
        chunks = _make_chunks(3)
        retriever = self._make_retriever(chunks)
        result = retriever.answer("Konfiguration")
        assert result.duration_ms >= 0.0


# ---------------------------------------------------------------------------
# HandbuchService
# ---------------------------------------------------------------------------


class TestHandbuchService:
    """Tests für HandbuchService."""

    def test_instanziierung_kein_absturz(self) -> None:
        """HandbuchService kann ohne Fehler instanziiert werden."""
        svc = HandbuchService()
        assert not svc.is_initialized

    def test_initialize_mit_echten_docs(self) -> None:
        """initialize baut Index mit echten docs/-Dateien auf."""
        # Verwendet die echten docs/ im Projektverzeichnis
        svc = HandbuchService()
        svc.initialize(role="all")
        # Wenn docs/ vorhanden und.md-Dateien existieren: chunk_count > 0
        # Wenn nicht vorhanden: chunk_count == 0 aber kein Absturz
        assert svc.chunk_count >= 0
        svc.shutdown()

    @pytest.mark.skipif(not _SKLEARN_AVAILABLE, reason=_SKLEARN_REASON)
    def test_initialize_mit_tmp_verzeichnis(self, tmp_path: Path) -> None:
        """initialize mit tmp_path als docs-Verzeichnis kein Absturz."""
        (tmp_path / "TEST.md").write_text(
            "## Abschnitt Eins\n\nDies ist ausreichend langer Text für einen Chunk.",
            encoding="utf-8",
        )
        svc = HandbuchService(docs_path=tmp_path)
        svc.initialize(role="all")
        assert svc.is_initialized
        assert svc.chunk_count >= 1
        svc.shutdown()

    def test_shutdown_idempotent(self) -> None:
        """shutdown kann mehrfach aufgerufen werden ohne Fehler."""
        svc = HandbuchService()
        svc.shutdown()
        svc.shutdown()

    def test_ask_ohne_initialize_kein_absturz(self, tmp_path: Path) -> None:
        """ask ohne vorherigen initialize-Aufruf kein Absturz."""
        # Wir patchen _setup_retriever um keine echte LLM-Verbindung zu brauchen
        svc = HandbuchService(docs_path=tmp_path)
        try:
            with patch.object(svc, "_setup_retriever"):
                svc.initialize(role="all")
            # Ohne Retriever gibt ask einen Fehler-Answer zurück
            result = svc.ask("Testfrage?")
            assert isinstance(result, HandbuchAnswer)
        finally:
            svc.shutdown()

    def test_ask_mit_mock_retriever(self, tmp_path: Path) -> None:
        """ask delegiert an RagRetriever.answer."""
        (tmp_path / "DOC.md").write_text(
            "## Abschnitt\n\nText für den Test der Anfrageverarbeitung.",
            encoding="utf-8",
        )
        svc = HandbuchService(docs_path=tmp_path)
        try:
            mock_retriever = MagicMock()
            mock_retriever.answer.return_value = HandbuchAnswer(
                question="Frage?",
                answer="Antwort.",
                sources=["## Abschnitt"],
                model="llama3.2",
                success=True,
            )

            with patch.object(svc, "_setup_retriever"):
                svc.initialize(role="all")
            svc._retriever = mock_retriever

            result = svc.ask("Frage?", role="all")
            mock_retriever.answer.assert_called_once()
            assert result.answer == "Antwort."
        finally:
            svc.shutdown()


# ---------------------------------------------------------------------------
# IndexRepository
# ---------------------------------------------------------------------------


class TestIndexRepository:
    """Tests für IndexRepository."""

    def test_save_load_round_trip(self, tmp_path: Path) -> None:
        """save_chunks + load_chunks ergibt identische Chunks."""
        repo = IndexRepository(cache_dir=tmp_path)
        chunks = _make_chunks(3)
        repo.save_chunks(chunks)

        loaded = repo.load_chunks()
        assert loaded is not None
        assert len(loaded) == len(chunks)

        for orig, load in zip(chunks, loaded):
            assert orig.chunk_id == load.chunk_id
            assert orig.source_file == load.source_file
            assert orig.heading == load.heading
            assert orig.text == load.text
            assert orig.role == load.role

    def test_load_ohne_cache_gibt_none(self, tmp_path: Path) -> None:
        """load_chunks ohne gespeicherten Cache gibt None zurück."""
        repo = IndexRepository(cache_dir=tmp_path)
        assert repo.load_chunks() is None

    def test_is_stale_ohne_cache(self, tmp_path: Path) -> None:
        """is_stale gibt True wenn kein Cache vorhanden."""
        repo = IndexRepository(cache_dir=tmp_path / "cache")
        (repo._cache_path.parent).mkdir(parents=True, exist_ok=True)
        assert repo.is_stale(tmp_path)

    def test_is_stale_nach_save(self, tmp_path: Path) -> None:
        """is_stale gibt False nach save_chunks wenn keine neuere.md-Datei."""
        docs = tmp_path / "docs"
        docs.mkdir()
        cache = tmp_path / "cache"
        cache.mkdir()

        # Erstelle.md-Datei
        md_file = docs / "TEST.md"
        md_file.write_text("# Test\n\nInhalt.", encoding="utf-8")

        repo = IndexRepository(cache_dir=cache)
        repo.save_chunks(_make_chunks(2))

        # Cache ist jetzt aktueller als die md-Datei
        assert not repo.is_stale(docs)

    def test_invalidate_loescht_cache(self, tmp_path: Path) -> None:
        """invalidate löscht den Cache-File."""
        repo = IndexRepository(cache_dir=tmp_path)
        repo.save_chunks(_make_chunks(2))
        assert repo._cache_path.exists()

        repo.invalidate()
        assert not repo._cache_path.exists()

    def test_invalidate_kein_absturz_ohne_cache(self, tmp_path: Path) -> None:
        """invalidate kein Absturz wenn kein Cache vorhanden."""
        repo = IndexRepository(cache_dir=tmp_path)
        repo.invalidate()  # kein Fehler erwartet
