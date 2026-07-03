"""
security_corpus — Kuratierter Offline-Wissenskorpus + Retrieval für das
RAG-Grounding des Security-Chats (Plan P1-1, Variante A).

Lädt die datierten, quellenbelegten Markdown-Dokumente unter
``resources/security_corpus/`` (OWASP/BSI/NIST/MITRE + Ollama-CVEs), chunkt sie
an den ``##``-Überschriften und beantwortet Ähnlichkeitssuchen via TF-IDF +
Cosinus. Bewusst self-contained (kein Cross-Tool-Import des handbuch_assistent):
das Handbuch-Muster ist NICHT 1:1 übertragbar (sein Filter schwärzt IOC-Hashes,
sein Prompt verbietet Security-Details). sklearn ist eine bereits vorhandene
Abhängigkeit; für den kleinen Korpus genügt TF-IDF ohne Vektor-DB.

Sicherheitsdesign (LLM08): nur kuratierte Quellen, kein User-Upload in die
Basis. Chunk-Texte werden als plain text in den Prompt eingebettet — kein eval.

Schichtzugehörigkeit: core/ — kein PySide6, keine Netzwerk-/GUI-Logik.
Aus ``tools/ki_integration/application/`` nach ``core/guardrails/`` gehoben zur tool-übergreifenden Nutzung im vereinten FINLAI-Assistenten.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from core.logger import get_logger

_log = get_logger(__name__)

#: Verzeichnis des ausgelieferten Korpus (Repo-Root/resources/security_corpus).
#: core/guardrails/corpus.py -> parents[2] == Repo-Root: vorher parents[3]
#: unter tools/ki_integration/application/).
_CORPUS_DIR = Path(__file__).resolve().parents[2] / "resources" / "security_corpus"

#: Relevanz-Schwelle (Cosinus). Ab hier gilt ein Treffer als "starker" Beleg,
#: der grounded beantwortet wird. Darunter: kein Kontext → Abstention/Modellwissen
#: laut System-Prompt (zweistufig). Pro Modell/Korpus kalibrierbar.
RELEVANCE_THRESHOLD = 0.12

#: Deutsche Funktionswoerter (Stopwords) in akzent-gestrippter Kleinschreibung
#: (passend zu strip_accents="unicode": ü→u, ö→o, ä→a). Ohne sie blaehen
#: Funktionswoerter die Cosinus-Aehnlichkeit auf und erzeugen Fehl-Treffer.
_GERMAN_STOPWORDS: list[str] = [
    "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer", "eines",
    "einem", "einen", "und", "oder", "aber", "ist", "sind", "war", "waren",
    "wird", "werden", "kann", "konnen", "muss", "mussen", "soll", "sollen",
    "von", "vom", "zu", "zum", "zur", "mit", "fur", "auf", "in", "im", "an",
    "am", "als", "auch", "nicht", "nur", "so", "wie", "was", "wer", "wann",
    "wo", "welche", "welcher", "welches", "dass", "dann", "noch", "schon",
    "bei", "aus", "nach", "uber", "unter", "vor", "durch", "gegen", "ohne",
    "um", "sein", "seine", "seiner", "ihre", "ihrer", "ich", "du", "er", "sie",
    "es", "wir", "ihr", "mir", "mich", "dir", "dich", "ihm", "ihn", "ihnen",
    "man", "kein", "keine", "diese", "dieser", "dieses", "etwa", "z", "b",
    "erzaehl", "erzaehle", "mehr", "sowie", "bzw", "etc", "werden", "haben",
    "hat", "wurde", "wurden", "einschliesslich", "sowohl",
]

_DEFAULT_TOP_K = 3
_MIN_CHUNK_CHARS = 40
_MAX_CHUNK_CHARS = 1500
_HEADING_RE = re.compile(r"^##\s+(.*)$")
_SNAPSHOT_RE = re.compile(r"Snapshot-Stichtag:\*\*\s*(\d{4}-\d{2}-\d{2})")


@dataclass(frozen=True)
class CorpusChunk:
    """Ein indizierter Abschnitt des Wissenskorpus.

    Attributes:
        source_file: Dateiname der Quelle (z. B. ``owasp_llm_top10_2025.md``).
        heading: Überschrift des Abschnitts (dient als Quellen-Label).
        text: Abschnittstext (für die Kontext-Einbettung).
    """

    source_file: str
    heading: str
    text: str


@dataclass(frozen=True)
class CorpusHit:
    """Ein Suchtreffer: Chunk plus Relevanz-Score."""

    chunk: CorpusChunk
    score: float


def _split_markdown(text: str, source_file: str) -> list[CorpusChunk]:
    """Zerlegt ein Markdown-Dokument in Chunks an den ``##``-Überschriften."""
    chunks: list[CorpusChunk] = []
    heading = ""
    body: list[str] = []

    def _flush() -> None:
        if not heading:
            return
        joined = "\n".join(body).strip()
        if len(joined) >= _MIN_CHUNK_CHARS:
            chunks.append(
                CorpusChunk(source_file, heading, joined[:_MAX_CHUNK_CHARS])
            )

    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            _flush()
            heading = m.group(1).strip()
            body = []
        elif heading:
            body.append(line)
    _flush()
    return chunks


class SecurityCorpus:
    """Lädt und durchsucht den kuratierten Security-Wissenskorpus.

    Args:
        corpus_dir: Verzeichnis mit den ``*.md``-Quellen (Default: das
            ausgelieferte ``resources/security_corpus``). Für Tests
            überschreibbar.
    """

    def __init__(self, corpus_dir: Path | None = None) -> None:
        self._dir = corpus_dir or _CORPUS_DIR
        self._chunks: list[CorpusChunk] = []
        self._vectorizer: object | None = None
        self._matrix: object | None = None
        self._fitted = False
        self._snapshot_date = "unbekannt"

    # ------------------------------------------------------------------
    def load(self) -> None:
        """Lädt alle Korpus-Dokumente und baut den TF-IDF-Index auf.

        Idempotent: ein bereits aufgebauter Index wird ersetzt. Dateien mit
        führendem Unterstrich (z. B. ``_meta.md``) werden nur für den
        Snapshot-Stichtag gelesen, nicht indiziert.
        """
        if not self._dir.is_dir():
            _log.warning("Security-Korpus-Verzeichnis fehlt: %s", self._dir)
            self._fitted = False
            return

        chunks: list[CorpusChunk] = []
        for md in sorted(self._dir.glob("*.md")):
            try:
                content = md.read_text(encoding="utf-8")
            except OSError as exc:
                _log.error("Korpus-Datei nicht lesbar (%s): %s", md.name, exc)
                continue
            if md.name.startswith("_"):
                stamp = _SNAPSHOT_RE.search(content)
                if stamp:
                    self._snapshot_date = stamp.group(1)
                continue
            chunks.extend(_split_markdown(content, md.name))

        self._chunks = chunks
        self._build_index()

    def _build_index(self) -> None:
        if not self._chunks:
            _log.warning("Security-Korpus leer — kein Index aufgebaut.")
            self._fitted = False
            return
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: PLC0415

            self._vectorizer = TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=10_000,
                strip_accents="unicode",
                sublinear_tf=True,
                stop_words=_GERMAN_STOPWORDS,
            )
            texts = [f"{c.heading}\n{c.text}" for c in self._chunks]
            self._matrix = self._vectorizer.fit_transform(texts)
            self._fitted = True
            _log.info("Security-Korpus: %d Chunks indiziert.", len(self._chunks))
        except ImportError:
            _log.error("scikit-learn fehlt — Security-RAG deaktiviert.")
            self._fitted = False
        except Exception as exc:  # noqa: BLE001
            _log.error("Security-Korpus-Index fehlgeschlagen: %s", exc)
            self._fitted = False

    # ------------------------------------------------------------------
    def search(self, query: str, top_k: int = _DEFAULT_TOP_K) -> list[CorpusHit]:
        """Sucht die top-k relevantesten Chunks zur Anfrage.

        Args:
            query: (bereits normalisierte) Nutzerfrage.
            top_k: Anzahl der Treffer.

        Returns:
            Liste von CorpusHit absteigend nach Score (nur Score > 0). Leer,
            wenn kein Index vorhanden oder die Anfrage leer ist.
        """
        if not self._fitted or not query.strip():
            return []
        try:
            import numpy as np  # noqa: PLC0415
            from sklearn.metrics.pairwise import cosine_similarity  # noqa: PLC0415

            q_vec = self._vectorizer.transform([query])  # type: ignore[union-attr]
            scores = cosine_similarity(q_vec, self._matrix).flatten()  # type: ignore[union-attr]
            k = min(top_k, len(self._chunks))
            top = np.argsort(scores)[::-1][:k]
            return [
                CorpusHit(self._chunks[i], float(scores[i]))
                for i in top
                if scores[i] > 0.0
            ]
        except Exception as exc:  # noqa: BLE001
            _log.error("Security-Korpus-Suche fehlgeschlagen: %s", exc)
            return []

    # ------------------------------------------------------------------
    @property
    def is_ready(self) -> bool:
        """True, wenn der Index aufgebaut wurde."""
        return self._fitted

    @property
    def chunk_count(self) -> int:
        """Anzahl indizierter Chunks."""
        return len(self._chunks)

    @property
    def snapshot_date(self) -> str:
        """Stichtag des Korpus-Snapshots (aus ``_meta.md``)."""
        return self._snapshot_date
