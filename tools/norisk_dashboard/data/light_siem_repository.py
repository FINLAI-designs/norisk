"""
light_siem_repository — EncryptedDatabase-Repository fuer den
Light-SIEM-Event-Pool.

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren, keine
application/gui-Importe.

Schema-Version 1:
- ``light_siem_events``: Zentrale Event-Tabelle mit Dedup-Index.

Die DB liegt unter ``~/.finlai/db/light_siem.db`` (encrypted via
SQLCipher). Separate DB vom ``norisk_dashboard``-Bestand, damit:
- Backup-Strategien (3f) das SIEM gezielt abdecken koennen,
- Performance-Profile (viele Events vs. wenig Dashboard-Daten) nicht
  vermischt werden,
- der Verzeichnis-Cleanup beim Deinstall einfach bleibt.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.norisk_dashboard.domain.light_siem_models import (
    DEFAULT_LOOKBACK_DAYS,
    EventSeverity,
    EventSource,
    LightSiemEvent,
    LightSiemSummary,
)

_log = get_logger(__name__)

DB_NAME: str = "light_siem"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS light_siem_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    source         TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    severity       TEXT NOT NULL,
    summary        TEXT NOT NULL,
    payload_json   TEXT NOT NULL DEFAULT '',
    dedup_hash     TEXT NOT NULL,
    ingested_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_siem_timestamp  ON light_siem_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_siem_source     ON light_siem_events(source);
CREATE INDEX IF NOT EXISTS idx_siem_severity   ON light_siem_events(severity);
CREATE UNIQUE INDEX IF NOT EXISTS uq_siem_dedup ON light_siem_events(dedup_hash);
"""

#: INSERT-Statement fuer Einzel- (:meth:`LightSiemRepository.add`) UND Batch-Pfad
#: (:meth:`LightSiemRepository.bulk_add` via executemany) — Single Source of Truth.
#: ``INSERT OR IGNORE`` macht den Dedup auf SQL-Ebene (dedup_hash UNIQUE).
_SQL_INSERT_EVENT = """
    INSERT OR IGNORE INTO light_siem_events
        (timestamp, source, event_type, severity, summary,
         payload_json, dedup_hash, ingested_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


def _event_params(event: LightSiemEvent) -> tuple:
    """Bindings fuer:data:`_SQL_INSERT_EVENT`."""
    return (
        event.timestamp.isoformat(),
        event.source.value,
        event.event_type,
        event.severity.value,
        event.summary,
        event.payload_json,
        event.dedup_hash,
        event.ingested_at.isoformat(),
    )


class LightSiemRepository:
    """CRUD-Repository fuer:class:`LightSiemEvent`.

    Dedup-Strategie: ``dedup_hash`` ist UNIQUE — ein doppelter INSERT
    schlaegt fehl, das wird in:meth:`add` abgefangen und liefert
    ``None`` zurueck. Damit koennen Adapter ihre Quellen einfach immer
    voll ingestieren, ohne selbst Dedup zu pflegen.
    """

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        """Initialisiert das Repository und legt das Schema an (idempotent).

        Args:
            db: Optionale:class:`EncryptedDatabase`-Instanz (typischerweise
                nur in Tests). Default: produktive ``light_siem``-DB.
        """
        self._db = db or EncryptedDatabase(DB_NAME)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add(self, event: LightSiemEvent) -> int | None:
        """Fuegt ein Event ein. Bei Dedup-Konflikt: ``None``.

        Dedup via ``INSERT OR IGNORE`` auf dem ``dedup_hash``-Unique-Index:
        ein doppelter Hash wird auf SQL-Ebene still uebersprungen
        (``cur.rowcount == 0``) — KEINE IntegrityError. Das ist bewusst so,
        weil eine geworfene UNIQUE-Exception vom ``EncryptedDatabase``-Wrapper
        VOR dem Abfangen hier als ``ERROR`` geloggt wird und beim idempotenten
        Voll-Ingest (Adapter liefern jede Quelle komplett) den Log mit
        Dutzenden Fehlzeilen pro Lauf flutet (Patrick-Log 2026-06-28).

        Args:
            event::class:`LightSiemEvent` mit ``id=None``.

        Returns:
            Die neue Datenbank-ID, oder ``None`` wenn der Dedup-Hash bereits
            existiert (idempotenter Re-Ingest).
        """
        with self._db.connection() as conn:
            cur = conn.execute(_SQL_INSERT_EVENT, _event_params(event))
            conn.commit()
            # rowcount == 0 -> Unique-Konflikt ignoriert (Dedup-Treffer).
            if cur.rowcount == 0:
                _log.debug(
                    "light_siem_dedup_hit hash=%s source=%s type=%s",
                    event.dedup_hash,
                    event.source.value,
                    event.event_type,
                )
                return None
            new_id = int(cur.lastrowid or 0)
        _log.info(
            "light_siem_event_added id=%s source=%s severity=%s",
            new_id,
            event.source.value,
            event.severity.value,
        )
        return new_id

    def bulk_add(self, events: list[LightSiemEvent]) -> tuple[int, int]:
        """Bulk-Insert in EINER Transaktion (executemany). Liefert ``(added, skipped_dedup)``.

        Perf: ein Connection-Open + ein Commit fuer den ganzen Ingest statt N
        Einzel-``add``-Opens (jeder Ingest-Lauf liefert je Quelle ~20-50 Events).
        Dedup bleibt via ``INSERT OR IGNORE`` auf SQL-Ebene; die Zahl tatsaechlich
        eingefuegter Zeilen kommt aus ``conn.total_changes`` (zuverlaessiger als
        executemany-rowcount), ``skipped`` ist der Rest. KEIN Per-Event-Log (der
        Einzelpfad loggt, der Bulk-Pfad nur eine Summe — sonst Log-Flut, 
        Dedup-Hinweis in:meth:`add`).
        """
        if not events:
            return (0, 0)
        params = [_event_params(e) for e in events]
        with self._db.connection() as conn:
            before = conn.total_changes
            conn.executemany(_SQL_INSERT_EVENT, params)
            conn.commit()
            added = conn.total_changes - before
        skipped = len(events) - added
        _log.info("light_siem_bulk_add added=%s skipped_dedup=%s", added, skipped)
        return (added, skipped)

    def delete_older_than(self, cutoff: datetime) -> int:
        """Loescht Events mit ``timestamp < cutoff``. Returns Anzahl.

        Wird in 3e fuer die Retention genutzt — Light-SIEM ist nicht
        archiv-fokussiert, alte Daten sollen aus der DB raus.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM light_siem_events WHERE timestamp < ?",
                (cutoff.isoformat(),),
            )
            conn.commit()
            deleted = int(cur.rowcount or 0)
        if deleted:
            _log.info(
                "light_siem_retention_purge deleted=%s cutoff=%s",
                deleted,
                cutoff.isoformat(),
            )
        return deleted

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_recent(
        self,
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
        limit: int = 200,
        *,
        now: datetime | None = None,
    ) -> list[LightSiemEvent]:
        """Liefert die neuesten Events im Lookback-Fenster.

        Args:
            lookback_days: Wie weit zurueck (Default 30 Tage).
            limit: Maximal-Anzahl Zeilen.
            now: Referenzzeit fuer das Fenster-Muster).
                ``None`` = Wanduhr — Produktiv-Verhalten unveraendert; Tests
                injizieren eine fixe Zeit statt zeitbombig gegen die Wanduhr
                zu rechnen.
        """
        cutoff = (now or datetime.now(UTC)) - timedelta(days=lookback_days)
        with self._db.connection() as conn:
            return self._events_from_conn(conn, cutoff=cutoff, limit=limit)

    def summary(
        self,
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
        *,
        now: datetime | None = None,
    ) -> LightSiemSummary:
        """Aggregierte Zahlen fuer die Dashboard-Card.

        Hat O(1) Cost wenn der Source/Severity-Index greift.

        Args:
            lookback_days: Wie weit zurueck (Default 30 Tage).
            now: Referenzzeit fuer das Fenster — ``None`` = Wanduhr.
        """
        cutoff = (now or datetime.now(UTC)) - timedelta(days=lookback_days)
        with self._db.connection() as conn:
            return self._summary_from_conn(
                conn, cutoff=cutoff, lookback_days=lookback_days
            )

    def load_dashboard_bundle(
        self,
        *,
        table_limit: int,
        chart_lookback_days: int,
        chart_limit: int,
        table_lookback_days: int = DEFAULT_LOOKBACK_DAYS,
        now: datetime | None = None,
    ) -> tuple[LightSiemSummary, list[LightSiemEvent], list[LightSiemEvent]]:
        """Summary + Tabellen-Events + Chart-Events in EINER Connection (Perf).

        Der Dashboard-Reload brauchte bisher 3 separate Connection-Opens
        (summary + 2x list_recent). Diese Methode buendelt sie in EINEN Open —
        verhaltensneutral (identische Fenster/Limits/Queries), nur ohne den
        doppelten PRAGMA-Setup. Tabelle + Summary teilen das
        ``table_lookback_days``-Fenster (Default 30 wie zuvor), das Chart sein
        eigenes ``chart_lookback_days``-Fenster.

        Returns:
            ``(summary, table_events, chart_events)``.
        """
        ref = now or datetime.now(UTC)
        table_cutoff = ref - timedelta(days=table_lookback_days)
        chart_cutoff = ref - timedelta(days=chart_lookback_days)
        with self._db.connection() as conn:
            summary = self._summary_from_conn(
                conn, cutoff=table_cutoff, lookback_days=table_lookback_days
            )
            table_events = self._events_from_conn(
                conn, cutoff=table_cutoff, limit=table_limit
            )
            chart_events = self._events_from_conn(
                conn, cutoff=chart_cutoff, limit=chart_limit
            )
        return (summary, table_events, chart_events)

    # ------------------------------------------------------------------
    # Interne Query-Helfer (teilen EINE Connection — siehe load_dashboard_bundle)
    # ------------------------------------------------------------------

    def _events_from_conn(
        self, conn: object, *, cutoff: datetime, limit: int
    ) -> list[LightSiemEvent]:
        """Liest Events ab ``cutoff`` (DESC, ``limit``) auf einer offenen Conn."""
        rows = conn.execute(
            """
            SELECT id, timestamp, source, event_type, severity, summary,
                   payload_json, dedup_hash, ingested_at
            FROM light_siem_events
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (cutoff.isoformat(), int(limit)),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def _summary_from_conn(
        self, conn: object, *, cutoff: datetime, lookback_days: int
    ) -> LightSiemSummary:
        """Aggregiert total/severity/source ab ``cutoff`` auf einer offenen Conn."""
        total_row = conn.execute(
            "SELECT COUNT(*), MAX(timestamp) FROM light_siem_events "
            "WHERE timestamp >= ?",
            (cutoff.isoformat(),),
        ).fetchone()
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) FROM light_siem_events "
            "WHERE timestamp >= ? GROUP BY severity",
            (cutoff.isoformat(),),
        ).fetchall()
        src_rows = conn.execute(
            "SELECT source, COUNT(*) FROM light_siem_events "
            "WHERE timestamp >= ? GROUP BY source",
            (cutoff.isoformat(),),
        ).fetchall()
        total = int(total_row[0] or 0)
        latest_iso = total_row[1]
        latest = datetime.fromisoformat(latest_iso) if latest_iso else None
        by_severity: dict[EventSeverity, int] = {s: 0 for s in EventSeverity}
        for sev_str, count in sev_rows:
            by_severity[EventSeverity.from_value(sev_str)] = int(count)
        by_source: dict[EventSource, int] = {s: 0 for s in EventSource}
        for src_str, count in src_rows:
            by_source[EventSource.from_value(src_str)] = int(count)
        return LightSiemSummary(
            total_events=total,
            by_severity=by_severity,
            by_source=by_source,
            critical_count=by_severity.get(EventSeverity.CRITICAL, 0),
            latest_timestamp=latest,
            lookback_days=lookback_days,
        )

    # ------------------------------------------------------------------
    # Row-Konverter
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_event(row) -> LightSiemEvent:  # noqa: ANN001 — sqlite-Row
        return LightSiemEvent(
            id=int(row[0]),
            timestamp=_parse_iso_utc(row[1]),
            source=EventSource.from_value(row[2]),
            event_type=row[3],
            severity=EventSeverity.from_value(row[4]),
            summary=row[5],
            payload_json=row[6] or "",
            dedup_hash=row[7] or "",
            ingested_at=_parse_iso_utc(row[8]),
        )


def _parse_iso_utc(value: str | None) -> datetime:
    """Parst einen ISO-Timestamp, Fallback ``datetime.now(UTC)``."""
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
