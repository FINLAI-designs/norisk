"""
test_document_scanner_quarantine.

Deckt:mod:`tools.document_scanner.application.quarantine_manager`
ab — keine GUI, kein Magika, kein validate_import. Reiner File-IO-Test
auf einem tmp-Pfad.

Pruefungen:

1. ``quarantine(path)`` legt einen neuen Slot mit UUID-Unterordner an,
   kopiert die Datei und setzt Read-Only-Bit.
2. ``quarantine`` raises ``FileNotFoundError`` fuer nicht-existente
   Quellen und Pfade die keine Datei sind.
3. SHA-256 stimmt mit ``hashlib`` ueber die Original-Datei ueberein.
4. ``remove`` raeumt einen Slot inklusive Read-Only-Datei auf.
5. ``cleanup_all`` raeumt mehrere Slots auf und gibt Anzahl zurueck.
6. ``QUARANTINE_ROOT`` haengt unter ``tempfile.gettempdir``.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from tools.document_scanner.application.quarantine_manager import (
    QUARANTINE_ROOT,
    QuarantineManager,
)


def test_quarantine_root_unter_tempdir() -> None:
    """Wurzel muss im System-Temp liegen."""
    assert str(QUARANTINE_ROOT).startswith(tempfile.gettempdir())
    assert QUARANTINE_ROOT.name == "norisk_quarantine"


def test_quarantine_legt_slot_an(tmp_path: Path) -> None:
    src = tmp_path / "harmlos.txt"
    src.write_text("hello", encoding="utf-8")
    qm = QuarantineManager(root=tmp_path / "q")

    entry = qm.quarantine(src)

    assert entry.quarantine_dir.exists()
    assert entry.stored_path.exists()
    assert entry.original_name == "harmlos.txt"
    assert entry.size_bytes == 5
    # SHA-256 muss zur Quelle passen
    expected = hashlib.sha256(b"hello").hexdigest()
    assert entry.sha256 == expected
    # Read-Only-Bit gesetzt — auf Windows funktioniert chmod 0o444 nur
    # eingeschraenkt, deshalb pruefen wir nur dass die Datei nicht
    # mit Schreibzugriff geoeffnet werden kann.
    with pytest.raises((PermissionError, OSError)):
        entry.stored_path.write_text("uebermalt")


def test_quarantine_unbekannte_datei_wirft(tmp_path: Path) -> None:
    qm = QuarantineManager(root=tmp_path / "q")
    with pytest.raises(FileNotFoundError):
        qm.quarantine(tmp_path / "nicht_da.bin")


def test_quarantine_directory_als_quelle_wirft(tmp_path: Path) -> None:
    qm = QuarantineManager(root=tmp_path / "q")
    with pytest.raises(FileNotFoundError):
        qm.quarantine(tmp_path)


def test_remove_loescht_slot(tmp_path: Path) -> None:
    src = tmp_path / "a.bin"
    src.write_bytes(b"\x00\x01\x02")
    qm = QuarantineManager(root=tmp_path / "q")
    entry = qm.quarantine(src)

    qm.remove(entry)
    assert not entry.quarantine_dir.exists()


def test_remove_doppelt_kein_crash(tmp_path: Path) -> None:
    """remove muss idempotent sein — Slot weg → kein Fehler."""
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    qm = QuarantineManager(root=tmp_path / "q")
    entry = qm.quarantine(src)

    qm.remove(entry)
    qm.remove(entry)  # darf nicht crashen
    assert not entry.quarantine_dir.exists()


def test_cleanup_all_raeumt_alles(tmp_path: Path) -> None:
    qm = QuarantineManager(root=tmp_path / "q")
    for i in range(3):
        f = tmp_path / f"file_{i}.txt"
        f.write_text("x")
        qm.quarantine(f)

    removed = qm.cleanup_all()
    assert removed == 3
    # Root bleibt bestehen (wird ja immer wieder gebraucht)
    assert qm.root.exists()
    #... aber leer
    assert not any(qm.root.iterdir())


def test_cleanup_all_kein_root_kein_fehler(tmp_path: Path) -> None:
    """Wenn der Root irgendwie weg ist → 0, kein Crash."""
    qm = QuarantineManager(root=tmp_path / "q")
    qm.root.rmdir()  # Root entfernen
    assert qm.cleanup_all() == 0
