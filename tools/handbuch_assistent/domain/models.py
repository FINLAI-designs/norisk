"""
models — Domain-Modelle des Handbuch-Assistenten.

Enthält ausschließlich Datenklassen ohne Seiteneffekte.
Keine externen Abhängigkeiten — nur Python-Standardbibliothek.

Schichtzugehörigkeit: domain/ — keine Imports aus application/,
data/ oder gui/. Keine Netzwerk- oder Dateioperationen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DocumentChunk:
    """Ein Textabschnitt aus einem Handbuch-Dokument.

    Entsteht beim Zerlegen von Markdown-Dateien an Überschriften.
    Bildet die atomare Einheit der TF-IDF-Indexierung.

    Attributes:
        chunk_id: Eindeutige ID (UUID4 als String).
        source_file: Dateiname der Quelldatei, z. B. ``"ANWENDERHANDBUCH.md"``.
        heading: Abschnittsüberschrift, z. B. ``"## Installation"``.
        text: Vollständiger Textinhalt des Abschnitts.
        role: Zugeordnete Benutzerrolle: ``"anwender"``,
                     ``"entwickler"`` oder ``"all"``.
        char_count: Zeichenanzahl des Textes (ohne Überschrift).
    """

    chunk_id: str
    source_file: str
    heading: str
    text: str
    role: str
    char_count: int = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "char_count", len(self.text))


@dataclass(frozen=True)
class RetrievalResult:
    """Ergebnis eines einzelnen Abrufvorgangs aus dem TF-IDF-Index.

    Attributes:
        chunk: Der abgerufene Textabschnitt.
        score: Cosinus-Ähnlichkeit zur Anfrage (0.0–1.0).
    """

    chunk: DocumentChunk
    score: float


@dataclass(frozen=True)
class HandbuchAnswer:
    """Vollständige Antwort des Handbuch-Assistenten auf eine Frage.

    Attributes:
        question: Ursprüngliche Nutzerfrage.
        answer: Generierte Antwort des LLM.
        sources: Liste der verwendeten Abschnittsüberschriften.
        model: Verwendetes LLM-Modell, z. B. ``"llama3.2"``.
        retrieved_chunks: Top-k Abschnitte die als Kontext genutzt wurden.
        duration_ms: Gesamtdauer in Millisekunden.
        success: False wenn LLM oder Retrieval fehlgeschlagen.
        error_message: Fehlerbeschreibung wenn success=False.
    """

    question: str
    answer: str
    sources: list[str]
    model: str
    retrieved_chunks: list[RetrievalResult] = field(default_factory=list)
    duration_ms: float = 0.0
    success: bool = True
    error_message: str = ""
