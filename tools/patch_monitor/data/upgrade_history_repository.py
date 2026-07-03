"""upgrade_history_repository — Audit-Persistenz fuer Patch-Upgrade-Aktionen.

 / PM-2.x Stop-Step B. Append-only Audit-Trail jeder
``WingetUpgradeExecutor.upgrade``-Aktion: was, wann, von welcher Version,
auf welche, mit welchem Outcome. Quelle fuer:

* den Live-Log-Panel im Patch-Monitor (Verlauf der letzten N Installs)
* die Hardening-Score-Trend-Linie (Patrick-Diskussion 2026-05-11: jedes
  Update senkt nominell die CVE-Exposition — Trend-Effekt sichtbar im
  Hardening-Gauge)
* spaetere Compliance-Berichte (Patch-SLA, Steuerberater-Audit)

Designziele (analog ``cyber_dashboard/data/briefing_history_repository.py``):

* EncryptedDatabase-Pflicht (SQLCipher, separate DB ``upgrade_history``)
* Append-only — kein UPDATE / DELETE in Production (Purge nur via
  Retention-Methode)
* Stabile ``id`` via ``uuid4`` (Backup-/Restore-portierbar)
* ``PRAGMA user_version`` fuer zukuenftige Migrationen P2-Pattern)
* Keine PII — winget_id ist Produkt-Identifier, kein User-Pfad

Schichtzugehoerigkeit: ``data/`` (Repository-Adapter fuer den
:class:`tools.patch_monitor.application.batch_upgrade_service.BatchUpgradeService`).
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from core.patch_upgrade import UpgradeResult, UpgradeStatus

log = get_logger(__name__)

_DB_NAME = "upgrade_history"
_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS upgrade_history (
    id            TEXT PRIMARY KEY,
    created_at    INTEGER NOT NULL,
    winget_id     TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    version_from  TEXT,
    version_to    TEXT,
    status        TEXT NOT NULL,
    exit_code     INTEGER,
    duration_ms   INTEGER NOT NULL,
    error         TEXT
);

CREATE INDEX IF NOT EXISTS idx_upgrade_history_created
    ON upgrade_history(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_upgrade_history_winget_id
    ON upgrade_history(winget_id);
"""


@dataclass(frozen=True)
class UpgradeHistoryEntry:
    """Ein persistierter Upgrade-Versuch.

    Attributes:
        id: UUID4 als Hex-String.
        created_at: Zeitpunkt der Aktion (UTC).
        winget_id: Produkt-Id (z. B. ``"Mozilla.Firefox"``).
        display_name: User-lesbarer Name aus der Request-Phase.
        version_from: Installierte Version vor dem Upgrade (oder ``None``).
        version_to: Ziel-Version (oder ``None``).
        status: Wert aus:class:`core.patch_upgrade.UpgradeStatus`.
        exit_code: winget Exit-Code (``None`` bei TIMEOUT / SKIPPED).
        duration_ms: Wandzeit des Subprocess in Millisekunden.
        error: Kurztext bei Fehler, sonst ``None``.
    """

    id: str
    created_at: datetime
    winget_id: str
    display_name: str
    version_from: str | None
    version_to: str | None
    status: UpgradeStatus
    exit_code: int | None
    duration_ms: int
    error: str | None


class UpgradeHistoryRepository:
    """Persistiert Patch-Upgrade-Versuche in einer eigenen SQLCipher-DB.

    Nutzung::

        repo = UpgradeHistoryRepository
        repo.record(
            winget_id="Mozilla.Firefox",
            display_name="Mozilla Firefox",
            version_from="123.0",
            version_to="124.0",
            result=upgrade_result,
)
    """

    def __init__(self) -> None:
        """Initialisiert die DB und legt das Schema an.

        Setzt ``PRAGMA user_version`` auf:data:`_SCHEMA_VERSION` fuer
        zukuenftige Migrations-Checks.
        """
        self._db = EncryptedDatabase(_DB_NAME)
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            # ``PRAGMA user_version = N`` akzeptiert keine Parameter-
            # Bindings — sicher hier, weil _SCHEMA_VERSION ein Modul-
            # Konstante ist.
            conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")  # noqa: S608

    def get_schema_version(self) -> int:
        """Liefert die aktuelle ``PRAGMA user_version`` der DB."""
        with self._db.connection() as conn:
            row = conn.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row else 0

    def record(
        self,
        *,
        winget_id: str,
        display_name: str,
        version_from: str | None,
        version_to: str | None,
        result: UpgradeResult,
    ) -> str:
        """Persistiert einen Upgrade-Versuch.

        Args:
            winget_id: Produkt-Id.
            display_name: User-lesbarer Name.
            version_from: Installierte Version (oder ``None``).
            version_to: Ziel-Version (oder ``None``).
            result: Vollstaendiges:class:`UpgradeResult` aus dem Executor.

        Returns:
            Die generierte UUID4 als Hex-String.
        """
        entry_id = uuid.uuid4().hex
        now = int(time.time())
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO upgrade_history(
                    id, created_at, winget_id, display_name,
                    version_from, version_to,
                    status, exit_code, duration_ms, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    now,
                    winget_id,
                    display_name,
                    version_from,
                    version_to,
                    str(result.status.value),
                    result.exit_code,
                    result.duration_ms,
                    result.error,
                ),
            )
        return entry_id

    def list_recent(self, limit: int = 50) -> list[UpgradeHistoryEntry]:
        """Liefert die ``limit`` neuesten Eintraege (created_at DESC)."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, winget_id, display_name,
                       version_from, version_to,
                       status, exit_code, duration_ms, error
                FROM upgrade_history
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def list_for_id(
        self, winget_id: str, *, limit: int = 20
    ) -> list[UpgradeHistoryEntry]:
        """Liefert die letzten Eintraege fuer eine bestimmte ``winget_id``."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, winget_id, display_name,
                       version_from, version_to,
                       status, exit_code, duration_ms, error
                FROM upgrade_history
                WHERE winget_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (winget_id, limit),
            ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def count(self) -> int:
        """Anzahl persistierter Eintraege."""
        with self._db.connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM upgrade_history").fetchone()[0]

    def purge_older_than(self, days: int) -> int:
        """Loescht Eintraege aelter als ``days`` Tage.

        Args:
            days: Maximales Alter in Tagen (>0).

        Returns:
            Anzahl geloeschter Zeilen.
        """
        if days <= 0:
            raise ValueError("days muss > 0 sein")
        cutoff = int(time.time()) - days * 86400
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM upgrade_history WHERE created_at < ?",
                (cutoff,),
            )
            return cur.rowcount


def _row_to_entry(row: Iterable) -> UpgradeHistoryEntry:
    """Mapt eine sqlite3-Row in:class:`UpgradeHistoryEntry`."""
    (
        entry_id,
        created_at,
        winget_id,
        display_name,
        version_from,
        version_to,
        status_str,
        exit_code,
        duration_ms,
        error,
    ) = row
    return UpgradeHistoryEntry(
        id=entry_id,
        created_at=datetime.fromtimestamp(created_at, tz=UTC),
        winget_id=winget_id,
        display_name=display_name,
        version_from=version_from,
        version_to=version_to,
        status=UpgradeStatus(status_str),
        exit_code=exit_code,
        duration_ms=duration_ms,
        error=error,
    )
