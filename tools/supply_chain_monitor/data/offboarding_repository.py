"""
offboarding_repository — Persistierung von Vendor-Off-Boardings.

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren.

Schema-Version 4-i, 2026-05-15):

- ``offboardings`` — eine Zeile pro Vendor (UNIQUE auf ``vendor_id`` →
  max. 1 Off-Boarding pro Vendor).
- ``offboarding_checks`` — Default + Custom-Eintraege pro Off-Boarding.

Author: Patrick Riederich
Version: 0.1-i, 2026-05-15)
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.supply_chain_monitor.domain.models import (
    OffBoarding,
    OffBoardingCheck,
    OffBoardingChecklistEntry,
    OffBoardingStatus,
)

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS offboardings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id     INTEGER NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'in_progress',
    reason        TEXT NOT NULL DEFAULT '',
    started_at    TEXT NOT NULL,
    completed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_offboardings_status
  ON offboardings(status);

CREATE TABLE IF NOT EXISTS offboarding_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    offboarding_id  INTEGER NOT NULL,
    check_key       TEXT,
    custom_label    TEXT NOT NULL DEFAULT '',
    is_custom       INTEGER NOT NULL DEFAULT 0,
    is_done         INTEGER NOT NULL DEFAULT 0,
    notes           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_offboarding_checks_offb
  ON offboarding_checks(offboarding_id);
"""


class OffBoardingRepository:
    """CRUD + Checklist-Replace fuer Off-Boardings."""

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        self._db = db or EncryptedDatabase("supply_chain_monitor")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            conn.commit()

    # ------------------------------------------------------------------
    # OffBoarding
    # ------------------------------------------------------------------

    def add(self, offboarding: OffBoarding) -> int:
        """Legt eine neue Off-Boarding-Instanz an.

        Raises:
            ValueError: Wenn fuer ``vendor_id`` bereits eine Instanz
                existiert (UNIQUE-Verstoss).
        """
        with self._db.connection() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO offboardings
                        (vendor_id, status, reason, started_at, completed_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        int(offboarding.vendor_id),
                        offboarding.status.value,
                        offboarding.reason,
                        offboarding.started_at.isoformat(),
                        offboarding.completed_at.isoformat()
                        if offboarding.completed_at is not None
                        else None,
                    ),
                )
                conn.commit()
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                if "unique" in msg and "vendor_id" in msg:
                    raise ValueError(
                        f"Off-Boarding fuer vendor_id={offboarding.vendor_id} "
                        "existiert bereits."
                    ) from exc
                raise
        new_id = int(cur.lastrowid or 0)
        _log.info("offboarding_added id=%s vendor_id=%s", new_id, offboarding.vendor_id)
        return new_id

    def get_by_id(self, offb_id: int) -> OffBoarding | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM offboardings WHERE id = ?",
                (int(offb_id),),
            ).fetchone()
        return self._row_to_offb(row) if row else None

    def get_for_vendor(self, vendor_id: int) -> OffBoarding | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM offboardings WHERE vendor_id = ?",
                (int(vendor_id),),
            ).fetchone()
        return self._row_to_offb(row) if row else None

    def list_all(self) -> list[OffBoarding]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM offboardings ORDER BY started_at DESC"
            ).fetchall()
        return [self._row_to_offb(r) for r in rows]

    def update(self, offboarding: OffBoarding) -> None:
        if offboarding.id is None:
            raise ValueError("OffBoarding.update braucht eine gesetzte id.")
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE offboardings
                SET status = ?, reason = ?, completed_at = ?
                WHERE id = ?
                """,
                (
                    offboarding.status.value,
                    offboarding.reason,
                    offboarding.completed_at.isoformat()
                    if offboarding.completed_at is not None
                    else None,
                    int(offboarding.id),
                ),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise ValueError(f"Kein Off-Boarding mit id={offboarding.id}.")

    def delete(self, offb_id: int) -> bool:
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM offboarding_checks WHERE offboarding_id = ?",
                (int(offb_id),),
            )
            cur = conn.execute(
                "DELETE FROM offboardings WHERE id = ?",
                (int(offb_id),),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0

    # ------------------------------------------------------------------
    # Checklist
    # ------------------------------------------------------------------

    def replace_checklist(
        self,
        offb_id: int,
        entries: list[OffBoardingChecklistEntry],
    ) -> None:
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM offboarding_checks WHERE offboarding_id = ?",
                (int(offb_id),),
            )
            for entry in entries:
                conn.execute(
                    """
                    INSERT INTO offboarding_checks
                        (offboarding_id, check_key, custom_label, is_custom,
                         is_done, notes)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(offb_id),
                        entry.check_key.value if entry.check_key else None,
                        entry.custom_label,
                        1 if entry.is_custom else 0,
                        1 if entry.is_done else 0,
                        entry.notes,
                    ),
                )
            conn.commit()

    def list_checklist(self, offb_id: int) -> list[OffBoardingChecklistEntry]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT id, offboarding_id, check_key, custom_label, is_custom, "
                "is_done, notes FROM offboarding_checks "
                "WHERE offboarding_id = ? ORDER BY is_custom ASC, id ASC",
                (int(offb_id),),
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    # ------------------------------------------------------------------
    # Row-Mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_offb(row) -> OffBoarding:  # noqa: ANN001
        completed_iso = row[5]
        return OffBoarding(
            id=int(row[0]),
            vendor_id=int(row[1]),
            status=_safe_status(row[2]),
            reason=row[3] or "",
            started_at=_parse_iso_utc(row[4]),
            completed_at=_parse_iso_utc(completed_iso) if completed_iso else None,
        )

    @staticmethod
    def _row_to_entry(row) -> OffBoardingChecklistEntry:  # noqa: ANN001
        key_value = row[2]
        return OffBoardingChecklistEntry(
            id=int(row[0]),
            offboarding_id=int(row[1]),
            check_key=(
                OffBoardingCheck.from_value(key_value) if key_value else None
            ),
            custom_label=row[3] or "",
            is_custom=bool(row[4]),
            is_done=bool(row[5]),
            notes=row[6] or "",
        )


def _safe_status(value: str) -> OffBoardingStatus:
    try:
        return OffBoardingStatus(value)
    except ValueError:
        return OffBoardingStatus.IN_PROGRESS


def _parse_iso_utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
