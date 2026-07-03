"""
vendor_repository — EncryptedDatabase-Repository fuer Vendor-Eintraege.

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren, keine
application/gui-Importe.

Schema-Version 1: Tabelle ``vendors`` mit
Kategorie, Kritikalitaet und Notes. AVV-Tracker (Iter 2c) bekommt eine
eigene Tabelle ``vendor_avv``; Auto-Detection-Quellen (Iter 2b) landen
in ``vendor_detections``.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.supply_chain_monitor.domain.models import Vendor, VendorCategory

_log = get_logger(__name__)

DB_NAME: str = "supply_chain_monitor"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vendors (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL,
    category           TEXT NOT NULL,
    criticality_score  INTEGER NOT NULL CHECK(criticality_score BETWEEN 1 AND 5),
    notes              TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vendors_name        ON vendors(name);
CREATE INDEX IF NOT EXISTS idx_vendors_category    ON vendors(category);
CREATE INDEX IF NOT EXISTS idx_vendors_criticality ON vendors(criticality_score DESC);
"""


class VendorRepository:
    """CRUD-Repository fuer:class:`Vendor` auf verschluesselter SQLite-DB."""

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        """Initialisiert das Repository und legt das Schema an (idempotent).

        Args:
            db: Optional vorgefertigte:class:`EncryptedDatabase`-Instanz.
                Wird typischerweise nur in Tests gesetzt (mit
                ``EncryptedDatabase("supply_chain_monitor_test")`` o.ae.).
                Default: ``EncryptedDatabase("supply_chain_monitor")``.
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

    def add(self, vendor: Vendor) -> int:
        """Fuegt einen neuen Vendor ein.

        Args:
            vendor::class:`Vendor` (id wird ignoriert).

        Returns:
            Die neu vergebene Datenbank-ID.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO vendors
                    (name, category, criticality_score, notes,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    vendor.name,
                    vendor.category.value,
                    vendor.criticality_score,
                    vendor.notes,
                    vendor.created_at.isoformat(),
                    vendor.updated_at.isoformat(),
                ),
            )
            conn.commit()
            new_id = int(cur.lastrowid or 0)
        _log.info("vendor_added id=%s name=%r", new_id, vendor.name)
        return new_id

    def get_by_id(self, vendor_id: int) -> Vendor | None:
        """Liefert einen Vendor anhand seiner ID oder ``None``."""
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT id, name, category, criticality_score, notes,
                       created_at, updated_at
                FROM vendors
                WHERE id = ?
                """,
                (int(vendor_id),),
            ).fetchone()
        return self._row_to_vendor(row) if row else None

    def list_all(self) -> list[Vendor]:
        """Liefert alle Vendoren, sortiert nach Kritikalitaet (desc) + Name."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, name, category, criticality_score, notes,
                       created_at, updated_at
                FROM vendors
                ORDER BY criticality_score DESC, name COLLATE NOCASE ASC
                """
            ).fetchall()
        return [self._row_to_vendor(row) for row in rows]

    def update(self, vendor: Vendor) -> None:
        """Aktualisiert einen bestehenden Vendor.

        Der ``updated_at``-Wert des Argumentes wird durch ``datetime.now(UTC)``
        ersetzt — Kommt der Aufrufer mit einem alten Stamp daher, ist das so
        gewollt unsichtbar.

        Args:
            vendor::class:`Vendor` mit gesetzter ``id``.

        Raises:
            ValueError: Wenn ``vendor.id`` fehlt oder kein Datensatz mit
                dieser ID existiert.
        """
        if vendor.id is None:
            raise ValueError("Vendor.update braucht eine gesetzte id.")
        now_iso = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE vendors
                SET name = ?, category = ?, criticality_score = ?, notes = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    vendor.name,
                    vendor.category.value,
                    vendor.criticality_score,
                    vendor.notes,
                    now_iso,
                    int(vendor.id),
                ),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise ValueError(f"Kein Vendor mit id={vendor.id} gefunden.")
        _log.info("vendor_updated id=%s", vendor.id)

    def delete(self, vendor_id: int) -> bool:
        """Loescht einen Vendor.

        Returns:
            ``True`` wenn eine Zeile geloescht wurde, sonst ``False``.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM vendors WHERE id = ?",
                (int(vendor_id),),
            )
            conn.commit()
            deleted = (cur.rowcount or 0) > 0
        if deleted:
            _log.info("vendor_deleted id=%s", vendor_id)
        return deleted

    @staticmethod
    def _row_to_vendor(row) -> Vendor:  # noqa: ANN001 — sqlite3.Row tuple-like
        return Vendor(
            id=int(row[0]),
            name=row[1],
            category=VendorCategory.from_value(row[2]),
            criticality_score=int(row[3]),
            notes=row[4] or "",
            created_at=_parse_iso_utc(row[5]),
            updated_at=_parse_iso_utc(row[6]),
        )


def _parse_iso_utc(value: str | None) -> datetime:
    """Parst einen ISO-Timestamp, fallback ``datetime.now(UTC)``."""
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
