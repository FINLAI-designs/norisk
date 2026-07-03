"""
handbook_retriever — Handbuch-Domänen-Retriever für den vereinten Assistenten.

Adapter, der die bestehenden Handbuch-Primitive (``DocumentLoader`` +
``ChunkIndexer``) hinter dem ``core.assistant.rag_service.Retriever``-Port
bereitstellt (Plan, B-3). Liefert ``RetrievedSource``-Treffer mit
``domain == DOMAIN_HANDBOOK``.

Bewusst OHNE watchdog-Observer (anders als ``HandbuchService``): der Lebenszyklus
(Index-Aufbau/-Neuaufbau) liegt beim aufrufenden Tab (Workstream C). Die
``GESPERRTE_DOKUMENTE``-Denyliste und die Rollen-/App-Filterung bleiben über
``DocumentLoader.load_for_role`` für ALLE Rollen erzwungen (Plan B-7).

Schichtzugehörigkeit: application/ (tools/) — darf ``core/`` importieren, nie
umgekehrt. Erfüllt den core-seitigen ``Retriever``-Port strukturell.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from core.assistant.rag_service import DEFAULT_TOP_K, RetrievedSource
from core.guardrails.guardrails import DOMAIN_HANDBOOK
from core.logger import get_logger
from tools.handbuch_assistent.application.chunk_indexer import ChunkIndexer
from tools.handbuch_assistent.application.document_loader import DocumentLoader

_log = get_logger(__name__)


class HandbookRetriever:
    """Retriever für das Anwenderhandbuch (Domäne ``handbook``).

    Baut den TF-IDF-Index lazy beim ersten ``retrieve`` rollen-/app-spezifisch
    auf. Schwelle effektiv > 0 (``ChunkIndexer.search`` verwirft score ≤ 0).

    Args:
        docs_path: Handbuch-Verzeichnis (Default: ausgeliefertes ``docs/``).
        role: Benutzerrolle für die Chunk-Filterung (Default ``"anwender"``).
        app_name: App-ID für die app-spezifische Handbuch-Auswahl.
    """

    def __init__(
        self,
        docs_path: Path | None = None,
        role: str = "anwender",
        app_name: str = "",
    ) -> None:
        self._loader = DocumentLoader(docs_path)
        self._indexer = ChunkIndexer()
        self._role = role
        self._app_name = app_name
        self._built = False

    def _ensure_index(self) -> None:
        """Baut den Index bei Bedarf einmalig auf (Denyliste/Rolle via Loader)."""
        if self._built:
            return
        chunks = self._loader.load_for_role(self._role, app_name=self._app_name)
        self._indexer.fit(chunks)
        self._built = True
        _log.info(
            "HandbookRetriever: Index aufgebaut — %d Chunks (role=%s, app=%s)",
            self._indexer.chunk_count,
            self._role,
            self._app_name or "(generisch)",
        )

    def retrieve(self, query: str, top_k: int = DEFAULT_TOP_K) -> list[RetrievedSource]:
        """Sucht die relevantesten Handbuch-Abschnitte zur Anfrage."""
        if not query.strip():
            return []
        self._ensure_index()
        results = self._indexer.search(query, top_k=top_k)
        return [
            RetrievedSource(
                domain=DOMAIN_HANDBOOK,
                label=res.chunk.heading,
                text=res.chunk.text,
                score=res.score,
                source_file=res.chunk.source_file,
            )
            for res in results
        ]

    def rebuild(self) -> None:
        """Erzwingt einen Index-Neuaufbau (z. B. nach Doku-Änderungen)."""
        self._built = False
        self._ensure_index()
