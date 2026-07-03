"""
index_repository — Persistenz-Adapter für den Handbuch-Chunk-Cache.

IndexRepository speichert die verarbeiteten DocumentChunks als JSON
in ``~/.finlai/handbuch_index.json`` und ermöglicht so schnellen
Neustart ohne erneutes Parsen der Markdown-Dateien.

Stale-Detection:
    is_stale vergleicht den mtime-Zeitstempel der neuesten.md-Datei
    mit dem gespeicherten Zeitstempel. Bei Änderungen wird der Cache
    als veraltet markiert und der Loader neu aufgerufen.

Sicherheitsdesign (STRIDE):
    Tampering: Nur bekannte Felder werden aus dem JSON gelesen.
    Info Discl.: Kein Logging von Chunk-Inhalten.

Schichtzugehörigkeit: data/ — Adapter, darf core/ importieren.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from pathlib import Path

from core.finlai_paths import finlai_dir
from core.logger import get_logger
from tools.handbuch_assistent.domain.models import DocumentChunk

_log = get_logger(__name__)

_CACHE_FILENAME = "handbuch_index.json"


class IndexRepository:
    """Liest und schreibt den DocumentChunk-Cache im ~/.finlai-Verzeichnis.

    Attributes:
        _cache_path: Vollständiger Pfad zur Cache-Datei.
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        """Initialisiert das IndexRepository.

        Args:
            cache_dir: Verzeichnis für die Cache-Datei.
                       Standard: ``~/.finlai/``.
        """
        if cache_dir is None:
            cache_dir = finlai_dir()
        cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_path = cache_dir / _CACHE_FILENAME

    # ------------------------------------------------------------------
    # Öffentliche Schnittstelle
    # ------------------------------------------------------------------

    def save_chunks(self, chunks: list[DocumentChunk]) -> None:
        """Speichert DocumentChunks als JSON-Cache.

        Args:
            chunks: Zu cachende Chunks.
        """
        try:
            data = {
                "version": 1,
                "count": len(chunks),
                "chunks": [
                    {
                        "chunk_id": c.chunk_id,
                        "source_file": c.source_file,
                        "heading": c.heading,
                        "text": c.text,
                        "role": c.role,
                    }
                    for c in chunks
                ],
            }
            self._cache_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            _log.debug("IndexRepository: %d Chunks gecacht", len(chunks))
        except OSError as exc:
            _log.error("IndexRepository.save_chunks() fehlgeschlagen: %s", exc)

    def load_chunks(self) -> list[DocumentChunk] | None:
        """Lädt DocumentChunks aus dem JSON-Cache.

        Returns:
            Liste von DocumentChunks oder None wenn kein Cache vorhanden
            oder der Cache beschädigt ist.
        """
        if not self._cache_path.exists():
            return None

        try:
            raw = self._cache_path.read_text(encoding="utf-8")
            data = json.loads(raw)

            if data.get("version") != 1:
                _log.warning("IndexRepository: Unbekannte Cache-Version — ignoriert")
                return None

            chunks: list[DocumentChunk] = []
            for entry in data.get("chunks", []):
                chunks.append(
                    DocumentChunk(
                        chunk_id=str(entry["chunk_id"]),
                        source_file=str(entry["source_file"]),
                        heading=str(entry["heading"]),
                        text=str(entry["text"]),
                        role=str(entry["role"]),
                    )
                )

            _log.debug("IndexRepository: %d Chunks geladen", len(chunks))
            return chunks

        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            _log.warning("IndexRepository: Cache beschädigt: %s", exc)
            return None
        except OSError as exc:
            _log.error("IndexRepository.load_chunks() fehlgeschlagen: %s", exc)
            return None

    def is_stale(self, docs_path: Path) -> bool:
        """Prüft ob der Cache älter ist als die neueste.md-Datei.

        Args:
            docs_path: Verzeichnis mit den Markdown-Dateien.

        Returns:
            True wenn kein Cache vorhanden oder mindestens eine.md-Datei
            neuer ist als der Cache.
        """
        if not self._cache_path.exists():
            return True

        try:
            cache_mtime = self._cache_path.stat().st_mtime

            for md_file in docs_path.glob("*.md"):
                if md_file.stat().st_mtime > cache_mtime:
                    return True

            return False

        except OSError as exc:
            _log.warning("IndexRepository.is_stale() Fehler: %s", exc)
            return True

    def invalidate(self) -> None:
        """Löscht den Cache (erzwingt Neuaufbau beim nächsten Start).

        Fehler beim Löschen werden nur gewarnt, nicht weitergeleitet.
        """
        try:
            if self._cache_path.exists():
                self._cache_path.unlink()
                _log.info("IndexRepository: Cache geleert")
        except OSError as exc:
            _log.warning("IndexRepository.invalidate() fehlgeschlagen: %s", exc)
