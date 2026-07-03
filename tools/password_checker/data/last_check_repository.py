"""
last_check_repository — Persistiert NUR den Zeitpunkt der letzten Passwort-
Prüfung / Cockpit-Inc-2).

KEIN Passwort, KEIN Hash — ausschliesslich ein Zeitstempel, damit die Cockpit-
Passwort-Kachel "zuletzt geprüft vor X Tagen" anzeigen kann. Single-Row-Tabelle
(fixe ``id = 1``, Upsert).

Schichtzugehörigkeit: data/ — nutzt EncryptedDatabase, keine application/gui-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger

_log = get_logger(__name__)

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS last_check ("
    " id INTEGER PRIMARY KEY CHECK(id = 1),"
    " checked_at TEXT NOT NULL"
    ")"
)


class LastCheckRepository:
    """Single-Row-Persistenz des letzten Passwort-Prüf-Zeitpunkts."""

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        """Initialisiert das Repository und legt das Schema idempotent an."""
        self._db = db or EncryptedDatabase("password_checker")
        with self._db.connection() as conn:
            conn.execute(_SCHEMA)
            conn.commit()

    def markiere_geprueft(self, zeitpunkt: datetime | None = None) -> None:
        """Speichert den Zeitpunkt der letzten Prüfung (Upsert auf ``id = 1``).

        Args:
            zeitpunkt: Zeitpunkt; Default ``datetime.now(UTC)``.
        """
        ts = (zeitpunkt or datetime.now(UTC)).isoformat()
        with self._db.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO last_check (id, checked_at) VALUES (1, ?)",
                (ts,),
            )
            conn.commit()

    def letzter_check(self) -> datetime | None:
        """Liefert den letzten Prüf-Zeitpunkt oder ``None`` (fail-soft)."""
        try:
            with self._db.connection() as conn:
                row = conn.execute(
                    "SELECT checked_at FROM last_check WHERE id = 1"
                ).fetchone()
        except Exception:  # noqa: BLE001 -- Cockpit-Metrik nie blockierend
            return None
        if row is None or row[0] is None:
            return None
        try:
            return datetime.fromisoformat(row[0])
        except (ValueError, TypeError):
            return None
