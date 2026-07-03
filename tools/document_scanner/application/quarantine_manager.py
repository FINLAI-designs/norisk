"""
quarantine_manager — Lifecycle-Verwaltung der Quarantaene-Ordner.

Jede Datei, die ein User per Drag&Drop in den Document Scanner zieht,
landet in einem isolierten Slot unter ``%TEMP%\\norisk_quarantine\\<uuid>``.
Der Manager kuemmert sich um:

- Slot-Erstellung mit eindeutiger UUID.
- Kopieren der Original-Datei in den Slot.
- Setzen des Read-Only-Bits via ``Path.chmod(0o444)`` (Windows + POSIX).
- SHA-256-Hash der gestoreten Datei (fuer spaeteren VirusTotal-Lookup).
- Cleanup einzelner Slots + des gesamten Quarantaene-Wurzelordners
  (z. B. beim App-Beenden).

Sicherheits-Invarianten (siehe internes Konzept):

- Quarantaene-Ordner wird **immer neu** angelegt — wir mischen nie
  fremde Dateien.
- Datei in der Quarantaene wird ``0o444`` gesetzt. Das verhindert auf
  Windows ein versehentliches Speichern-ueber durch Office/Reader und
  setzt das Read-Only-Bit, das Explorer beim Doppelklick warnen laesst.
  Iter 1 reicht das; harte ACL via ``icacls`` ist Iter 1+1.
- Auto-Cleanup ist Pflicht — sonst sammeln sich infizierte Dateien an.

Schichtzugehoerigkeit: application/ — darf domain/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from core.logger import get_logger
from tools.document_scanner.domain.models import QuarantineEntry

_log = get_logger(__name__)

#: Wurzel fuer alle Quarantaene-Slots. Unter Windows landet das in
#: ``%TEMP%\\norisk_quarantine`` (= ``C:\\Users\\<u>\\AppData\\Local\\Temp\\...``).
QUARANTINE_ROOT: Path = Path(tempfile.gettempdir()) / "norisk_quarantine"


def _sha256_of(path: Path) -> str:
    """Berechnet SHA-256 einer Datei in 64KiB-Chunks."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class QuarantineManager:
    """Verwalter der Quarantaene-Ordner.

    Eine Instanz pro App-Session reicht — der Manager haelt nichts
    persistent im Speicher (Slots werden bei jedem Aufruf frisch
    erstellt). Cleanup-Methoden sind idempotent.
    """

    def __init__(self, root: Path | None = None) -> None:
        """Initialisiert den Manager.

        Args:
            root: Optionaler abweichender Wurzelordner (z. B. fuer
                Tests). Default ist:data:`QUARANTINE_ROOT`.
        """
        self._root = root or QUARANTINE_ROOT
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        """Liefert die aktive Quarantaene-Wurzel."""
        return self._root

    def quarantine(self, source: Path) -> QuarantineEntry:
        """Kopiert eine Datei in einen neuen Quarantaene-Slot.

        Args:
            source: Pfad zur Original-Datei (User-Drag&Drop).

        Returns:
:class:`QuarantineEntry` mit allen Slot-Metadaten.

        Raises:
            FileNotFoundError: Wenn die Quelldatei nicht existiert.
            OSError: Bei IO-Fehlern (z. B. kein Schreibzugriff auf TEMP).
        """
        source = Path(source).resolve()
        if not source.exists():
            raise FileNotFoundError(f"Quelldatei nicht gefunden: {source}")
        if not source.is_file():
            raise FileNotFoundError(f"Quelle ist keine Datei: {source}")

        slot_uuid = uuid.uuid4()
        slot_dir = self._root / str(slot_uuid)
        slot_dir.mkdir(parents=True, exist_ok=False)

        target = slot_dir / source.name
        shutil.copy2(source, target)

        # Read-Only-Bit setzen — verhindert versehentliches Oeffnen.
        with suppress(OSError):
            target.chmod(0o444)

        size = target.stat().st_size
        sha = _sha256_of(target)

        entry = QuarantineEntry(
            uuid=slot_uuid,
            original_name=source.name,
            quarantine_dir=slot_dir,
            stored_path=target,
            sha256=sha,
            size_bytes=size,
            created_at=datetime.now(UTC),
        )
        _log.info(
            "Quarantaene-Slot angelegt: uuid=%s size=%d sha256=%s...",
            slot_uuid,
            size,
            sha[:12],
        )
        return entry

    def remove(self, entry: QuarantineEntry) -> None:
        """Loescht einen einzelnen Slot.

        Schluckt:class:`OSError` (Datei evtl. schon weg) — Cleanup
        soll nie crashen.

        Args:
            entry: Zu loeschender Slot.
        """
        with suppress(OSError):
            # Read-Only-Bit zuruecksetzen, damit rmtree die Datei loeschen darf
            entry.stored_path.chmod(0o600)
        with suppress(OSError):
            shutil.rmtree(entry.quarantine_dir, ignore_errors=True)
        _log.debug("Quarantaene-Slot entfernt: %s", entry.uuid)

    def cleanup_all(self) -> int:
        """Loescht den kompletten Quarantaene-Wurzelordner.

        Wird beim App-Beenden aufgerufen — sammelt alle Slots ein.
        Schluckt:class:`OSError` (Datei in Benutzung).

        Returns:
            Anzahl tatsaechlich entfernter Slot-Unterordner.
        """
        removed = 0
        if not self._root.exists():
            return 0
        for child in self._root.iterdir():
            if not child.is_dir():
                continue
            for entry in child.rglob("*"):
                with suppress(OSError):
                    entry.chmod(0o600)
            with suppress(OSError):
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        _log.info("Quarantaene-Cleanup: %d Slot(s) entfernt", removed)
        return removed
