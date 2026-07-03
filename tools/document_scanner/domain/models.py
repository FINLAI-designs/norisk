"""
models — Domain-Modelle fuer den Document Scanner.

Schichtzugehoerigkeit: domain/ — keine Importe aus application/data/gui,
keine ``core.security``-Imports (das ist die Application-Schicht).

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from uuid import UUID


class ScanVerdict(Enum):
    """Zusammengefasste Empfehlung fuer den User.

    Berechnet aus dem ``ValidationReport.risk_score`` plus Heuristik.
    """

    SAFE = "safe"  # nichts Auffaelliges
    SUSPICIOUS = "suspicious"  # MEDIUM/HIGH-Threats, vorsichtig
    DANGEROUS = "dangerous"  # CRITICAL-Threat ODER nicht parsebar


@dataclass(frozen=True)
class QuarantineEntry:
    """Ein Quarantaene-Slot fuer eine eingescannte Datei.

    Der Ordner liegt unter ``%TEMP%\\norisk_quarantine\\<uuid>\\`` und
    enthaelt die kopierte Original-Datei mit Read-Only-Bit.

    Attributes:
        uuid: Eindeutiger Bezeichner des Slots.
        original_name: Dateiname wie der User ihn beim Drop gesehen hat.
        quarantine_dir: Absoluter Pfad zum Slot-Ordner.
        stored_path: Absoluter Pfad zur kopierten Datei (read-only).
        sha256: SHA-256-Hash fuer spaeteren VirusTotal-Lookup.
        size_bytes: Originalgroesse der Datei.
        created_at: Erstellungszeit (UTC).
    """

    uuid: UUID
    original_name: str
    quarantine_dir: Path
    stored_path: Path
    sha256: str
    size_bytes: int
    created_at: datetime


@dataclass(frozen=True)
class DocumentScanResult:
    """Ergebnis eines Document-Scans.

    Wrappet den aus ``core.security.validate_import`` zurueckgegebenen
    ``ValidationReport`` und reichert ihn um Quarantaene-Metadaten und
    eine User-orientierte ``ScanVerdict``-Zusammenfassung an.

    Wir halten den ``ValidationReport`` als ``object`` (statt typisiert),
    damit der Domain-Layer keine ``core.security``-Importe braucht.
    Die Application-Schicht verstaut den Report typgerecht.

    Attributes:
        entry: Quarantaene-Eintrag.
        verdict: ``ScanVerdict`` (User-orientiert).
        risk_score: 0-100, aus ValidationReport.
        magika_label: Magika-erkannter Typ (z. B. ``"pdf"``).
        type_match: Magika-Typ vs. Datei-Endung konsistent?
        threats: Liste ``Threat``-Objekte aus ValidationReport.
        validation_report: Der Original-Report (zur Detailansicht).
        duration_ms: Gesamtdauer der Pipeline.
        scanned_at: Zeitpunkt des Scans (UTC).
    """

    entry: QuarantineEntry
    verdict: ScanVerdict
    risk_score: int
    magika_label: str
    type_match: bool
    threats: list = field(default_factory=list)
    validation_report: object = None
    duration_ms: float = 0.0
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
