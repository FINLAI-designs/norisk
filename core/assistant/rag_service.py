"""
rag_service — Domänen-Dispatch für das RAG des vereinten FINLAI-Assistenten.

Stellt einen einheitlichen Retrieval-Boundary über zwei getrennte
Wissensquellen bereit (Plan, B-2/B-3):

  * Handbuch-Domäne (``handbook``): Anwenderhandbuch-RAG, rollen-/app-gefiltert,
    Denyliste aktiv, Schwelle effektiv > 0 (der Indexer filtert score > 0).
  * Security-Domäne (``security``): kuratierter Offline-Korpus, öffentlich,
    Schwelle ≥ ``RELEVANCE_THRESHOLD`` (0.12).

Treffer beider Domänen werden auf den gemeinsamen Wert ``RetrievedSource``
abgebildet, der das ``domain``-Tag trägt — das vermeidet redundante
``domain``-Felder in den (je domänen-homogenen) Chunk-Klassen und liefert dem
UI die Gruppierung (📚 Handbuch / 🔒 Sicherheit).

Schichtzugehörigkeit: core/ — kein PySide6, keine Netzwerk-/GUI-Logik. Der
Handbuch-Retriever-Adapter (der ``tools/``-Primitive nutzt) lebt in
``tools/handbuch_assistent`` und erfüllt strukturell den ``Retriever``-Port.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from core.guardrails.corpus import RELEVANCE_THRESHOLD, SecurityCorpus
from core.guardrails.guardrails import DOMAIN_SECURITY
from core.logger import get_logger

_log = get_logger(__name__)

#: Standard-Anzahl Retrieval-Treffer pro Domäne.
DEFAULT_TOP_K = 3


@dataclass(frozen=True)
class RetrievedSource:
    """Ein domänen-getaggter Retrieval-Treffer (vereinte Sicht über beide RAGs).

    Attributes:
        domain: Quell-Domäne (``DOMAIN_HANDBOOK`` / ``DOMAIN_SECURITY``).
        label: Anzeige-Label (Abschnittsüberschrift) für das Quellen-Panel.
        text: Abschnittstext (Kontext-Einbettung in den Prompt).
        score: Relevanz-Score (Cosinus-Ähnlichkeit).
        source_file: Dateiname der Quelle (für Provenienz/Transparenz).
    """

    domain: str
    label: str
    text: str
    score: float
    source_file: str = ""


class Retriever(Protocol):
    """Port: liefert domänen-getaggte Treffer zu einer (normalisierten) Anfrage."""

    def retrieve(self, query: str, top_k: int = DEFAULT_TOP_K) -> list[RetrievedSource]:
        """Sucht die relevantesten Abschnitte zur Anfrage."""
        ...


class RagService:
    """Dispatcht Retrieval an domänen-spezifische Retriever, B-3).

    Args:
        retrievers: Mapping Domäne → Retriever. Domänen ohne registrierten
            Retriever (z. B. ``offtopic``) liefern keine Treffer.
    """

    def __init__(self, retrievers: dict[str, Retriever]) -> None:
        self._retrievers = dict(retrievers)

    def retrieve(
        self, query: str, domain: str, top_k: int = DEFAULT_TOP_K
    ) -> list[RetrievedSource]:
        """Liefert die Treffer der zur Domäne passenden Wissensquelle.

        Args:
            query: Bereits normalisierte Nutzerfrage.
            domain: Ziel-Domäne (``handbook`` / ``security``).
            top_k: Anzahl der Treffer.

        Returns:
            Liste von ``RetrievedSource`` (leer bei fehlendem Retriever, leerer
            Anfrage oder Retrieval-Fehler — fail-soft, der System-Prompt regelt
            dann die Abstention).
        """
        retriever = self._retrievers.get(domain)
        if retriever is None or not query.strip():
            return []
        try:
            return retriever.retrieve(query, top_k=top_k)
        except Exception as exc:  # noqa: BLE001 — RAG fail-soft, kein harter Stop
            _log.error(
                "RAG-Retrieval (%s) fehlgeschlagen: %s", domain, type(exc).__name__
            )
            return []

    @staticmethod
    def group_by_domain(
        sources: Iterable[RetrievedSource],
    ) -> dict[str, list[RetrievedSource]]:
        """Gruppiert Treffer nach Domäne (für das gruppierte Quellen-Panel)."""
        grouped: dict[str, list[RetrievedSource]] = {}
        for source in sources:
            grouped.setdefault(source.domain, []).append(source)
        return grouped


class SecurityCorpusRetriever:
    """Retriever für den Security-Korpus (Domäne ``security``).

    Lädt den kuratierten Offline-Korpus lazy (fail-soft, analog
    ``ChatService._resolve_corpus``) und gibt nur Treffer ab der Relevanz-
    Schwelle zurück.

    Args:
        corpus: Vorgeladener Korpus (Tests) oder ``None`` (lazy-Aufbau des
            ausgelieferten Korpus).
        threshold: Mindest-Relevanz (Default ``RELEVANCE_THRESHOLD`` = 0.12).
    """

    def __init__(
        self,
        corpus: SecurityCorpus | None = None,
        threshold: float = RELEVANCE_THRESHOLD,
    ) -> None:
        self._corpus = corpus
        self._threshold = threshold
        self._loaded = corpus is not None and corpus.is_ready

    def _resolve(self) -> SecurityCorpus | None:
        """Liefert den (lazy geladenen) Korpus oder None (fail-soft)."""
        if self._corpus is None:
            self._corpus = SecurityCorpus()
        if not self._loaded:
            self._corpus.load()
            self._loaded = True
        return self._corpus if self._corpus.is_ready else None

    def retrieve(self, query: str, top_k: int = DEFAULT_TOP_K) -> list[RetrievedSource]:
        """Sucht Security-Korpus-Belege oberhalb der Relevanz-Schwelle."""
        corpus = self._resolve()
        if corpus is None or not query.strip():
            return []
        hits = corpus.search(query, top_k=top_k)
        return [
            RetrievedSource(
                domain=DOMAIN_SECURITY,
                label=hit.chunk.heading,
                text=hit.chunk.text,
                score=hit.score,
                source_file=hit.chunk.source_file,
            )
            for hit in hits
            if hit.score >= self._threshold
        ]

    @property
    def snapshot_date(self) -> str:
        """Stichtag des Korpus-Snapshots (für die Transparenz-Anzeige)."""
        return self._corpus.snapshot_date if self._corpus is not None else "unbekannt"
