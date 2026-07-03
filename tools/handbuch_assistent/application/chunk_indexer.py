"""
chunk_indexer — TF-IDF-Indexierung von DocumentChunks.

ChunkIndexer baut einen TF-IDF-Vektorraum aus DocumentChunk-Texten
und ermöglicht semantische Ähnlichkeitssuche via Cosinus-Ähnlichkeit.

Technische Details:
    - TfidfVectorizer(ngram_range=(1, 2), max_features=10_000)
    - Cosinus-Ähnlichkeit via sklearn.metrics.pairwise.cosine_similarity
    - top-k Ergebnisse werden nach Score absteigend sortiert zurückgegeben
    - Leere Korpusse werden abgefangen (gibt leere Liste zurück)

Sicherheitsdesign (STRIDE):
    Tampering: Eingaben werden nur als Text verarbeitet — kein eval.
    DoS: max_features=10_000 begrenzt Speicherbedarf.

Schichtzugehörigkeit: application/ — kein GUI, keine DB-Aufrufe.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from tools.handbuch_assistent.domain.models import DocumentChunk, RetrievalResult

_log = get_logger(__name__)

_NGRAM_RANGE = (1, 2)
_MAX_FEATURES = 10_000


class ChunkIndexer:
    """TF-IDF-Index über DocumentChunk-Texte mit Cosinus-Ähnlichkeitssuche.

    Attributes:
        _chunks: Die indizierten DocumentChunks (in Trainingsreihenfolge).
        _vectorizer: Trainierter TfidfVectorizer.
        _matrix: TF-IDF-Matrix (scipy sparse, shape: n_chunks × n_features).
        _fitted: True wenn fit erfolgreich aufgerufen wurde.
    """

    def __init__(self) -> None:
        """Initialisiert einen leeren ChunkIndexer."""
        self._chunks: list[DocumentChunk] = []
        self._vectorizer: object | None = None
        self._matrix: object | None = None
        self._fitted = False

    # ------------------------------------------------------------------
    # Öffentliche Schnittstelle
    # ------------------------------------------------------------------

    def fit(self, chunks: list[DocumentChunk]) -> None:
        """Baut den TF-IDF-Index aus den übergebenen Chunks.

        Bestehender Index wird ersetzt. Leere Chunk-Listen werden
        akzeptiert aber nicht indexiert (kein Fehler).

        Args:
            chunks: Zu indexierende DocumentChunks.
        """
        if not chunks:
            _log.warning("ChunkIndexer.fit(): Keine Chunks — Index bleibt leer")
            self._fitted = False
            return

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: PLC0415

            self._chunks = list(chunks)
            texts = [c.text for c in self._chunks]

            self._vectorizer = TfidfVectorizer(
                ngram_range=_NGRAM_RANGE,
                max_features=_MAX_FEATURES,
                strip_accents="unicode",
                sublinear_tf=True,
            )
            self._matrix = self._vectorizer.fit_transform(texts)
            self._fitted = True

            _log.info(
                "ChunkIndexer: %d Chunks indexiert (%d Features)",
                len(self._chunks),
                self._matrix.shape[1],  # type: ignore[union-attr]
            )

        except ImportError:
            _log.error(
                "scikit-learn nicht installiert — "
                "bitte 'pip install scikit-learn' ausführen"
            )
        except Exception as exc:
            _log.error("ChunkIndexer.fit() fehlgeschlagen: %s", exc)

    def search(self, query: str, top_k: int = 3) -> list[RetrievalResult]:
        """Sucht die top-k ähnlichsten Chunks zur Anfrage.

        Args:
            query: Suchbegriff oder Nutzerfrage.
            top_k: Anzahl der zurückzugebenden Ergebnisse.

        Returns:
            Liste von RetrievalResult, absteigend nach Score sortiert.
            Leer wenn kein Index vorhanden oder query leer ist.
        """
        if not self._fitted or not query.strip():
            return []

        try:
            import numpy as np  # noqa: PLC0415
            from sklearn.metrics.pairwise import cosine_similarity  # noqa: PLC0415

            q_vec = self._vectorizer.transform([query])  # type: ignore[union-attr]
            scores = cosine_similarity(q_vec, self._matrix).flatten()  # type: ignore[union-attr]

            # top-k Indizes absteigend nach Score
            k = min(top_k, len(self._chunks))
            top_indices = np.argsort(scores)[::-1][:k]

            results = [
                RetrievalResult(chunk=self._chunks[i], score=float(scores[i]))
                for i in top_indices
                if scores[i] > 0.0
            ]
            return results

        except Exception as exc:
            _log.error("ChunkIndexer.search() fehlgeschlagen: %s", exc)
            return []

    @property
    def chunk_count(self) -> int:
        """Anzahl der indizierten Chunks."""
        return len(self._chunks)

    @property
    def is_fitted(self) -> bool:
        """True wenn der Index aufgebaut wurde."""
        return self._fitted
