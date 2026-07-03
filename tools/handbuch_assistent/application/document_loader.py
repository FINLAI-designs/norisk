"""
document_loader — Lädt und zerlegt Handbuch-Markdown-Dateien in Chunks.

DocumentLoader liest alle ``.md``-Dateien aus dem konfigurierten
Handbuch-Verzeichnis und zerlegt sie an Markdown-Überschriften in
DocumentChunk-Objekte für die spätere TF-IDF-Indexierung.

Rollen-Mapping:
    ``ANWENDERHANDBUCH.md`` → role="anwender"
    ``ENTWICKLERHANDBUCH.md`` → role="entwickler"
    alle übrigen.md-Dateien → role="all"

``load_for_role("anwender")`` liefert Anwender- + "all"-Chunks.
``load_for_role("entwickler")`` liefert Entwickler- + "all"-Chunks.
``load_for_role("all")`` liefert alle Chunks.

Sicherheitsdesign (STRIDE):
    Tampering: Nur.md-Dateien unterhalb des konfigurierten
                 Pfads werden geladen — kein Path-Traversal.
    Info Discl.: Chunk-Inhalte werden nicht geloggt.

Schichtzugehörigkeit: application/ — kein GUI, keine DB-Aufrufe.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from core.logger import get_logger
from tools.handbuch_assistent.domain.models import DocumentChunk

_log = get_logger(__name__)

# Rollen-Mapping: Teile des Dateinamens → Rolle
_ROLE_MAP: dict[str, str] = {
    "ANWENDERHANDBUCH": "anwender",
    "ENTWICKLERHANDBUCH": "entwickler",
}

# Minimale Chunk-Länge (zu kurze Abschnitte werden verworfen)
_MIN_CHUNK_CHARS = 30

# Mapping: App-ID → app-spezifisches Anwenderhandbuch
_HANDBUCH_MAP: dict[str, str] = {
    "finlai": "ANWENDERHANDBUCH_FINLAI.md",
    "norisk": "ANWENDERHANDBUCH_NORISK.md",
    "automate": "ANWENDERHANDBUCH_AUTOMATE.md",
}

# Dokumente die für ALLE Anwender geladen werden (unabhängig von der App)
_GEMEINSAME_ANWENDER_DOKUMENTE: frozenset[str] = frozenset({"BASISINFO.md"})


def get_anwender_dokumente(app_name: str = "") -> frozenset[str]:
    """Gibt die Allowlist der Anwender-Dokumente für die aktive App zurück.

    Args:
        app_name: App-ID (``"finlai"``, ``"norisk"``, ``"automate"``).
                  Leer oder unbekannt → generisches ANWENDERHANDBUCH.md (Fallback).

    Returns:
        frozenset mit erlaubten Dateinamen für role='anwender'.
    """
    handbuch = _HANDBUCH_MAP.get(app_name, "ANWENDERHANDBUCH.md")
    return frozenset({handbuch}) | _GEMEINSAME_ANWENDER_DOKUMENTE


# Backward-Compat: Bestandscode und Tests können ANWENDER_DOKUMENTE weiter importieren.
# Enthält den generischen Fallback (app_name="").
ANWENDER_DOKUMENTE: frozenset[str] = get_anwender_dokumente("")

# Denylist: Diese Dateien werden für KEINE Rolle geladen (auch nicht für "all").
# Enthält Security-sensible Dokumente die niemals in den RAG-Kontext gelangen dürfen.
GESPERRTE_DOKUMENTE: frozenset[str] = frozenset(
    {
        "SECURITY.md",
        "THREAT_MODEL.md",
        "ANALYSE_DB_FAILURES.md",
        "ANALYSE_LICENSE_MANAGER.md",
        "ANALYSE_NVD_API_KEY.md",
        "ANALYSE_RATE_LIMITING.md",
        "analyse_vba_pruefregeln.md",
        "ENTWICKLERHANDBUCH.md",
        "ENTWICKLERTAGEBUCH.md",
    }
)


class DocumentLoader:
    """Lädt Markdown-Dateien und zerlegt sie in DocumentChunks.

    Attributes:
        _docs_path: Verzeichnis mit den Handbuch-Markdown-Dateien.
    """

    def __init__(self, docs_path: Path | None = None) -> None:
        """Initialisiert den DocumentLoader.

        Args:
            docs_path: Pfad zum Handbuch-Verzeichnis.
                       Standard: ``docs/`` relativ zum Arbeitsverzeichnis.
        """
        if docs_path is None:
            # Relativ zum Paket-Root (3 Ebenen über dieser Datei)
            base = Path(__file__).resolve().parents[3]
            docs_path = base / "docs"
        self._docs_path = docs_path

    # ------------------------------------------------------------------
    # Öffentliche Schnittstelle
    # ------------------------------------------------------------------

    def load_for_role(
        self, role: str = "all", app_name: str = ""
    ) -> list[DocumentChunk]:
        """Lädt alle Chunks die für die angegebene Rolle relevant sind.

        Args:
            role: ``"anwender"``, ``"entwickler"`` oder ``"all"``.
            app_name: App-ID für app-spezifische Handbuch-Auswahl
                      (``"finlai"``, ``"norisk"``, ``"automate"``).
                      Leer → generischer Fallback.

        Returns:
            Liste von DocumentChunks sortiert nach Quelldatei und Reihenfolge.
        """
        if not self._docs_path.is_dir():
            _log.warning("Handbuch-Verzeichnis nicht gefunden: %s", self._docs_path)
            return []

        anwender_docs = get_anwender_dokumente(app_name)
        all_chunks: list[DocumentChunk] = []

        for md_file in sorted(self._docs_path.glob("*.md")):
            filename = md_file.name

            # Gesperrte Dokumente werden für KEINE Rolle geladen
            if filename in GESPERRTE_DOKUMENTE:
                _log.debug("Übersprungen (gesperrt): %s", filename)
                continue

            # Anwender-Rolle: nur Dokumente aus der app-spezifischen Allowlist laden
            if role == "anwender" and filename not in anwender_docs:
                _log.debug("Übersprungen (nicht in Anwender-Allowlist): %s", filename)
                continue

            file_role = self._detect_role(filename)

            # Übrige Rollen: nur passende Rolle oder "all"
            if role not in ("anwender", "all") and file_role not in ("all", role):
                continue

            try:
                text = md_file.read_text(encoding="utf-8")
                chunks = self._split_into_chunks(text, filename, file_role)
                all_chunks.extend(chunks)
                _log.debug(
                    "Geladen: %s — %d Chunks (role=%s)",
                    filename,
                    len(chunks),
                    file_role,
                )
            except OSError as exc:
                _log.error("Datei konnte nicht gelesen werden: %s — %s", filename, exc)

        _log.info(
            "DocumentLoader: %d Chunks für Rolle '%s' geladen",
            len(all_chunks),
            role,
        )
        return all_chunks

    def available_files(self) -> list[str]:
        """Gibt alle verfügbaren Markdown-Dateinamen zurück.

        Returns:
            Sortierte Liste von Dateinamen.
        """
        if not self._docs_path.is_dir():
            return []
        return sorted(f.name for f in self._docs_path.glob("*.md"))

    # ------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ------------------------------------------------------------------

    def _split_into_chunks(
        self, text: str, source_file: str, role: str
    ) -> list[DocumentChunk]:
        """Zerlegt Markdown-Text an Überschriften (# und ##) in Chunks.

        Args:
            text: Vollständiger Markdown-Inhalt einer Datei.
            source_file: Dateiname für die chunk_id-Generierung.
            role: Rolle der Quelldatei.

        Returns:
            Liste von DocumentChunks ohne Leer-Chunks.
        """
        # Markdown-Überschriften als Trennpunkte: # Titel oder ## Abschnitt
        heading_pattern = re.compile(r"^(#{1,3}\s.+)$", re.MULTILINE)

        chunks: list[DocumentChunk] = []
        sections = heading_pattern.split(text)

        # sections = [pre-text, heading1, content1, heading2, content2,...]
        # Erstes Element ist Text vor der ersten Überschrift
        current_heading = source_file  # Fallback wenn kein Heading
        buffer = sections[0].strip()

        if buffer and len(buffer) >= _MIN_CHUNK_CHARS:
            chunks.append(self._make_chunk(current_heading, buffer, source_file, role))

        # Überschrift-Content-Paare verarbeiten
        it = iter(sections[1:])
        for heading in it:
            content = next(it, "").strip()
            current_heading = heading.strip()

            if content and len(content) >= _MIN_CHUNK_CHARS:
                chunks.append(
                    self._make_chunk(current_heading, content, source_file, role)
                )

        return chunks

    @staticmethod
    def _detect_role(filename: str) -> str:
        """Ermittelt die Rolle anhand des Dateinamens.

        Args:
            filename: Dateiname ohne Pfad, z. B. ``"ANWENDERHANDBUCH.md"``.

        Returns:
            Erkannte Rolle oder ``"all"`` als Fallback.
        """
        upper = filename.upper()
        for keyword, role in _ROLE_MAP.items():
            if keyword in upper:
                return role
        return "all"

    @staticmethod
    def _make_chunk(
        heading: str, text: str, source_file: str, role: str
    ) -> DocumentChunk:
        """Erstellt einen DocumentChunk mit neuer UUID.

        Args:
            heading: Abschnittsüberschrift.
            text: Textinhalt.
            source_file: Quelldateiname.
            role: Benutzerrolle.

        Returns:
            Neuer DocumentChunk.
        """
        return DocumentChunk(
            chunk_id=str(uuid.uuid4()),
            source_file=source_file,
            heading=heading,
            text=text,
            role=role,
        )
