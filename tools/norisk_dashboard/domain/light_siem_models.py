"""
light_siem_models — Domain-Modelle fuer den Light-SIEM-Event-Pool.

Iter 3d, 2026-05-16, NoRisk-Audit-Paket-3): Sammelt
Sicherheits-Events aus Patch-Monitor, System-Scanner und Cert-Monitor
in einem zentralen Pool. Die Anomalie-Heuristik in 3e (gewichteter
Anomalie-Score, Trend) liest aus diesem Pool — also muss er pro Source
einen einheitlichen Event-Shape liefern.

Patrick-Direktive 2026-05-16: Light-SIEM lebt als neues Modul im
``norisk_dashboard`` (kein eigenes Tool) — dieselbe DB-Schicht, Dashboard-
Card als GUI-Anker.

Schichtzugehoerigkeit: domain/ — keine Importe aus application/data/gui.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

MAX_EVENT_TYPE_LENGTH: int = 100
MAX_SUMMARY_LENGTH: int = 500
MAX_PAYLOAD_LENGTH: int = 4000

# Anzahl Tage, ueber die der Dashboard-Stream Standard-maessig zurueckblickt.
DEFAULT_LOOKBACK_DAYS: int = 30


class EventSource(Enum):
    """Quelle eines Light-SIEM-Events.

    Wir tracken nur Tools, die ein produktives Event-Konzept haben —
    nicht jeder NoRisk-Scanner liefert SIEM-relevante Daten. Erweiterungen
    in 3d-ii und nachfolgenden Iterationen moeglich.
    """

    PATCH_MONITOR = "patch_monitor"  # Patch-Verzoegerungen, Update-Failures
    SYSTEM_SCANNER = "system_scanner"  # Compliance-Banner, EOL-Befunde
    CERT_MONITOR = "cert_monitor"  # Zertifikats-Ablauf, Issuer-Aenderungen
    SUPPLY_CHAIN_MONITOR = "supply_chain_monitor"  # AVV-Renewals, Detection-Pending
    AWARENESS_TRACKER = "awareness_tracker"  # Schulungs-Renewals, Phishing-Klick-Spikes
    OTHER = "other"  # Fallback fuer noch nicht klassifizierte Quellen

    @classmethod
    def from_value(cls, value: str) -> EventSource:
        """Robuste Konvertierung aus DB-String, Fallback ``OTHER``."""
        try:
            return cls(value)
        except ValueError:
            return cls.OTHER


class EventSeverity(Enum):
    """Schweregrad eines Light-SIEM-Events.

    Wir lehnen uns an Syslog-Severities an, lassen aber DEBUG/EMERGENCY
    weg, weil das fuer ein KMU-SIEM ueberzogen ist.
    """

    INFO = "info"  # Reine Information (Scan abgeschlossen, etc.)
    WARN = "warn"  # Warnung (Renewal in <30 Tagen, EOL <180 Tage)
    ERROR = "error"  # Fehler (Patch-Failure, Cert-Issuer-Change)
    CRITICAL = "critical"  # Kritisch (EOL bereits ueberschritten, AVV overdue)

    @classmethod
    def from_value(cls, value: str) -> EventSeverity:
        """Robuste Konvertierung aus DB-String, Fallback ``INFO``."""
        try:
            return cls(value)
        except ValueError:
            return cls.INFO

    @property
    def numeric_weight(self) -> int:
        """Numerisches Gewicht fuer Heuristiken (3e Anomalie-Score).

        INFO=1, WARN=3, ERROR=5, CRITICAL=10. Die Skala ist nicht-linear:
        ein einzelnes CRITICAL-Event soll mehr in den Score eingehen
        als 9 INFO-Events.
        """
        return {
            EventSeverity.INFO: 1,
            EventSeverity.WARN: 3,
            EventSeverity.ERROR: 5,
            EventSeverity.CRITICAL: 10,
        }[self]


@dataclass(frozen=True)
class LightSiemEvent:
    """Ein normalisiertes Sicherheits-Event im Light-SIEM-Pool.

    Alle Quellen liefern Events in diesem Shape — der ``payload_json`` ist
    optional und enthaelt source-spezifische Detail-Daten (z. B. die
    CVE-ID bei einem Patch-Event, das Cert-Issuer-Pair bei einem Cert-
    Event). Die GUI rendert nur die normalisierten Felder; ``payload`` ist
    fuer 3e + Debug-Anzeigen.

    ``dedup_hash`` wird beim Persistieren generiert und sorgt dafuer, dass
    dieselbe Detektion bei wiederholten Scans nicht n-mal in der DB landet.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        timestamp: Zeitpunkt des Original-Events (UTC). NICHT die
                      DB-Insertion-Zeit — wenn der Adapter einen alten
                      Patch-Eintrag findet, soll der Original-Zeitstempel
                      erhalten bleiben.
        source::class:`EventSource`.
        event_type: Source-internes Klassifikations-Label (z. B.
                      ``"patch_failed"``, ``"cert_expiring"``). Max. 100 Z.
        severity::class:`EventSeverity`.
        summary: Einzeiliger Klartext fuer den Stream-View
                      (1..500 Zeichen, getrimmt).
        payload_json: Optional, Source-spezifische Detail-Daten als
                      JSON-String (Domain bewertet den Inhalt nicht).
        dedup_hash: SHA-256 Hex (16 Zeichen) ueber
                      ``(source, event_type, summary)`` — gemeinsamer
                      Schluessel fuer das Dedup-Filter im Repository.
        ingested_at: DB-Insertion-Zeit (wird vom Repo gesetzt; in der
                      Domain initialisiert mit ``now``).
    """

    id: int | None
    timestamp: datetime
    source: EventSource
    event_type: str
    severity: EventSeverity
    summary: str
    payload_json: str = ""
    dedup_hash: str = ""
    ingested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        event_type = self.event_type.strip()
        if not event_type:
            raise ValueError("LightSiemEvent.event_type darf nicht leer sein.")
        if len(event_type) > MAX_EVENT_TYPE_LENGTH:
            raise ValueError(
                f"LightSiemEvent.event_type darf max. {MAX_EVENT_TYPE_LENGTH} "
                f"Zeichen haben."
            )
        summary = self.summary.strip()
        if not summary:
            raise ValueError("LightSiemEvent.summary darf nicht leer sein.")
        if len(summary) > MAX_SUMMARY_LENGTH:
            # Wir kuerzen statt zu werfen — Adapter koennten lange Logs liefern.
            summary = summary[:MAX_SUMMARY_LENGTH]
        if len(self.payload_json) > MAX_PAYLOAD_LENGTH:
            raise ValueError(
                f"LightSiemEvent.payload_json darf max. {MAX_PAYLOAD_LENGTH} "
                f"Zeichen haben."
            )
        if event_type != self.event_type:
            object.__setattr__(self, "event_type", event_type)
        if summary != self.summary:
            object.__setattr__(self, "summary", summary)
        # Dedup-Hash auto-berechnen wenn nicht gesetzt.
        if not self.dedup_hash:
            object.__setattr__(
                self, "dedup_hash", compute_dedup_hash(self.source, event_type, summary)
            )


def compute_dedup_hash(
    source: EventSource, event_type: str, summary: str
) -> str:
    """Berechnet einen stabilen Dedup-Schluessel fuer ein Event.

    Drei Felder gehen ein: ``source``, ``event_type``, ``summary``. Wenn
    derselbe Befund (gleicher Vendor, gleiches Patch, gleiche Issuer-CN)
    in zwei Scans erscheint, ergibt das denselben Hash — das Repository
    kann den zweiten Scan filtern.

    Args:
        source::class:`EventSource`.
        event_type: Source-internes Klassifikations-Label.
        summary: Normalisierter Klartext.

    Returns:
        Hex-Hash, 16 Zeichen lang (sha256-Anfang).
    """
    raw = f"{source.value}|{event_type.strip()}|{summary.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]  # noqa: S324 — Dedup-Hash, nicht Crypto


@dataclass(frozen=True)
class LightSiemSummary:
    """Aggregierte Kennzahlen ueber den aktuellen Event-Pool.

    Wird in der Dashboard-Card angezeigt und in 3e fuer die Anomalie-
    Heuristik weiterverwendet.

    Attributes:
        total_events: Gesamtanzahl Events im Lookback-Fenster.
        by_severity: Mapping ``{Severity: count}``.
        by_source: Mapping ``{Source: count}``.
        critical_count: Convenience-Feld (== by_severity[CRITICAL]).
        latest_timestamp: Neuestes Event im Pool (oder None).
        lookback_days: Mit welchem Lookback wurde aggregiert.
    """

    total_events: int
    by_severity: dict[EventSeverity, int]
    by_source: dict[EventSource, int]
    critical_count: int
    latest_timestamp: datetime | None
    lookback_days: int = DEFAULT_LOOKBACK_DAYS

    @property
    def is_empty(self) -> bool:
        return self.total_events == 0
